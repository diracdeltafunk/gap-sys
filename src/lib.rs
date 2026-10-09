#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
//! Raw libgap bindings plus a small Rust convenience layer.
//!
//! The `include!` below exposes the bindgen-generated C API almost verbatim.
//! The handwritten types in this file provide a safer path for common tasks:
//! initializing GAP, evaluating snippets, calling GAP functions, converting a
//! few primitive values, and keeping selected GAP objects alive across garbage
//! collections.
//!
//! GAP owns every `Obj`. A [`GapValue`] owns a GC root, so it can safely survive
//! later GAP calls. [`GapRef`] is the explicit low-level, unrooted handle for
//! code that can prove it will not cross a GAP allocation.
//!
//! # Threads and errors
//!
//! The wrapper methods may be called from any thread, one thread at a time
//! (the process-global runtime behind [`global`] enforces this with a mutex).
//! Every call into libgap runs inside libgap's `GAP_Enter()`/`GAP_Leave()`
//! bracket, which points GAP's conservative garbage collector at the calling
//! thread's stack and catches GAP errors that nothing else handles. GAP errors
//! are reported as `Err` values and leave the runtime usable.
//!
//! GAP releases before 4.11 have no `GAP_Enter()`. With those, GAP can only be
//! used from the thread that initialized it, and calling it from another
//! thread panics.

/// The bindgen-generated libgap API, re-exported at the crate root.
#[allow(clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
pub use bindings::*;

use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread::{self, ThreadId};

/// A live libgap interpreter instance.
///
/// `Gap` caches a handful of GAP globals and stream objects needed by the
/// wrapper methods; they stay rooted for the lifetime of the `Gap`. libgap
/// itself is process-global and not generally designed for independent
/// parallel runtimes, so callers should prefer [`global`] or [`with_gap`] when
/// sharing one interpreter across a program.
pub struct Gap {
    /// GAP's `PrintTo` function, cached as a raw GAP object for rendering.
    print_fn: Obj,
    /// GAP's `InputTextString` operation, used to feed strings to the reader.
    input_stream: Obj,
    /// GAP's `CallFuncList` operation, used to call non-function callables.
    call_func_list: Obj,
    /// Mutable GAP string that receives printed output.
    output_str_obj: Obj,
    /// GAP output stream handle wrapping `output_str_obj`.
    output_stream_handle: Obj,
}

// SAFETY: The Rust wrapper serializes access to the global runtime through a
// mutex. libgap remains process-global; this marker lets `Mutex<Gap>` live in a
// `static` while callers still need to avoid concurrent direct `Gap` instances.
unsafe impl Send for Gap {}

impl Drop for Gap {
    fn drop(&mut self) {
        let _ = protect(|| unsafe {
            SYSGAP_CloseOutput();
        });
        for obj in self.cached_objects() {
            unroot_obj(obj);
        }
    }
}

/// An unrooted handle to a GAP object.
///
/// This is a copyable Rust-side wrapper around GAP's raw `Obj` pointer. It is
/// not a Rust borrow and does not root the object with GAP's garbage collector.
/// It may become invalid after a GAP operation that allocates. Prefer
/// [`GapValue`], which is what the normal public API returns.
#[derive(Clone, Copy, Debug)]
pub struct GapRef {
    /// Raw GAP object pointer produced by libgap.
    ///
    /// The pointer is meaningful only while the libgap runtime is initialized
    /// and the object remains reachable or explicitly rooted.
    pub obj: Obj,
}

/// Deprecated name for [`GapRef`].
#[deprecated(since = "0.2.4", note = "renamed to `GapRef`")]
pub type GapElement = GapRef;

/// An owned, garbage-collector-rooted GAP value.
///
/// Cloning a `GapValue` adds another entry to the root table, and dropping it
/// removes one. This makes the wrapped GAP object safe to keep in Rust data
/// structures across GAP allocations.
#[derive(Debug)]
pub struct GapValue {
    /// The unrooted handle registered in `OBJ_REFS`.
    reference: GapRef,
}

/// Mutex guard for the process-global [`Gap`] runtime.
///
/// The guard dereferences to `Gap`, giving callers mutable access while keeping
/// all global interpreter use serialized.
pub struct GlobalGapGuard {
    /// The underlying lock guard held for the duration of the borrow.
    guard: MutexGuard<'static, Gap>,
}

impl fmt::Display for GapRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let cstr = CStr::from_ptr(GAP_CSTR_STRING(self.obj));
            write!(f, "{}", cstr.to_string_lossy())
        }
    }
}

impl fmt::Pointer for GapRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:p}", self.obj)
    }
}

/// Parses a hexadecimal address string into a raw GAP bag pointer.
///
/// This exists for compatibility with older call sites that serialized GAP
/// object addresses as strings. New code should pass `GapRef` or `GapValue`
/// values directly instead of round-tripping through text.
///
/// # Safety
///
/// The returned pointer is not validated. The caller must only use strings that
/// were produced from a live GAP object pointer in the same process and runtime.
unsafe fn hex_str_to_ptr(hex_str: &str) -> Result<Bag, std::num::ParseIntError> {
    let without_prefix = hex_str.trim_start_matches("0x");
    let addr = usize::from_str_radix(without_prefix, 16)?;
    Ok(addr as Bag)
}

/// Converts a textual raw pointer address into a `GapRef`.
///
/// This is intended only for legacy pointer-string interop. It panics if `s`
/// is not a valid hexadecimal address.
impl From<&str> for GapRef {
    fn from(s: &str) -> Self {
        GapRef {
            obj: unsafe { hex_str_to_ptr(s.trim()).unwrap() },
        }
    }
}

// Cloning and dropping a `GapValue` only touch the root table, which has its
// own lock. That is safe even while another thread holds the GAP runtime and
// is collecting garbage: the collector's mark callback holds the same lock, so
// it sees the table either before or after the change, and an object is never
// unrooted while some `GapValue` for it is still alive.
impl Clone for GapValue {
    fn clone(&self) -> Self {
        root_obj(self.reference.obj);
        Self {
            reference: self.reference,
        }
    }
}

impl Drop for GapValue {
    fn drop(&mut self) {
        unroot_obj(self.reference.obj);
    }
}

impl GapValue {
    /// Roots `reference` and returns an owned GAP value.
    ///
    /// The root is released when the returned `GapValue` is dropped.
    fn new(reference: GapRef) -> Self {
        root_obj(reference.obj);
        Self { reference }
    }

    /// Returns the unrooted handle for an explicitly low-level operation.
    ///
    /// The returned handle remains protected by this `GapValue`'s root for as
    /// long as this value is retained.
    pub fn as_unrooted(&self) -> GapRef {
        self.reference
    }
}

impl Deref for GlobalGapGuard {
    type Target = Gap;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for GlobalGapGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

/// Builder for configuring GAP initialization.
///
/// The builder currently supports choosing a runtime root. It is mainly useful
/// for initializing the process-global runtime with [`GapBuilder::init_global`]
/// before any code calls [`global`] or [`with_gap`].
#[derive(Debug, Clone, Default)]
pub struct GapBuilder {
    /// Optional GAP root containing `lib/init.g`.
    root: Option<PathBuf>,
}

impl GapBuilder {
    /// Creates a builder that uses the build-time or environment GAP root.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the GAP root used during runtime initialization.
    ///
    /// `root` must identify a GAP runtime tree containing `lib/init.g`.
    pub fn root<P: AsRef<Path>>(mut self, root: P) -> Self {
        self.root = Some(root.as_ref().to_path_buf());
        self
    }

    /// Initializes the process-global GAP runtime.
    ///
    /// This should be called at most once per process. If it is not called
    /// explicitly, [`global`] and [`with_gap`] lazily initialize the runtime
    /// using the default root. Returns an error if another caller already
    /// initialized the global runtime.
    pub fn init_global(self) -> Result<()> {
        let _init_guard = GLOBAL_GAP_INIT
            .lock()
            .map_err(|_| anyhow!("global GAP initialization mutex was poisoned"))?;
        if GLOBAL_GAP.get().is_some() {
            return Err(anyhow!("global GAP runtime is already initialized"));
        }

        let gap = match self.root {
            Some(root) => Gap::try_init_with_root(root)?,
            None => Gap::try_init()?,
        };
        GLOBAL_GAP
            .set(Mutex::new(gap))
            .map_err(|_| anyhow!("global GAP runtime is already initialized"))
    }
}

/// Initializes the process-global GAP runtime with default settings.
///
/// This is shorthand for `GapBuilder::new().init_global()`. Calling it is
/// optional; [`global`] and [`with_gap`] will initialize the runtime lazily if
/// needed.
pub fn init_global() -> Result<()> {
    GapBuilder::new().init_global()
}

/// Returns a locked handle to the process-global GAP runtime.
///
/// The runtime is initialized on first use. Holding the returned guard prevents
/// other threads from entering the shared runtime until the guard is dropped.
pub fn global() -> Result<GlobalGapGuard> {
    ensure_global()?;
    let guard = GLOBAL_GAP
        .get()
        .expect("global GAP should be initialized")
        .lock()
        .map_err(|_| anyhow!("global GAP runtime mutex was poisoned"))?;
    Ok(GlobalGapGuard { guard })
}

/// Runs `f` with mutable access to the process-global GAP runtime.
///
/// This is a small convenience wrapper around [`global`]. It keeps the lock
/// scoped to the closure and propagates both initialization and callback errors.
pub fn with_gap<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&mut Gap) -> Result<T>,
{
    let mut gap = global()?;
    f(&mut gap)
}

/// Evaluates GAP source text in the process-global runtime.
///
/// This is shorthand for `global()?.eval(cmd)`. It is useful for small
/// programs and tests; use [`with_gap`] or [`global`] when several operations
/// should share one lock scope.
pub fn eval(cmd: &str) -> Result<GapValue> {
    global()?.eval(cmd)
}

/// Deprecated alias for [`eval`].
#[deprecated(since = "0.2.4", note = "renamed to `eval`")]
pub fn gap_eval(cmd: &str) -> Result<GapValue> {
    eval(cmd)
}

impl Gap {
    /// Initializes GAP or panics with a short error message.
    ///
    /// Prefer [`Gap::try_init`] in libraries or tools that can surface a useful
    /// diagnostic to callers.
    pub fn init() -> Gap {
        Self::try_init().expect("Unable to initialize GAP")
    }

    /// Initializes GAP using the default runtime root.
    ///
    /// The root comes from the `GAP_SYS_ROOT` environment variable when it is
    /// set; otherwise it uses the root discovered by `build.rs`.
    pub fn try_init() -> Result<Gap> {
        let root = default_gap_root();
        Self::try_init_with_root(root)
    }

    /// Initializes GAP with an explicit root or panics.
    ///
    /// Prefer [`Gap::try_init_with_root`] when the caller can recover from or
    /// report initialization errors.
    pub fn init_with_root<P: AsRef<Path>>(root: P) -> Gap {
        Self::try_init_with_root(root).expect("Unable to initialize GAP")
    }

    /// Initializes GAP with an explicit runtime root.
    ///
    /// The root must contain `lib/init.g`. The implementation passes `-l` with
    /// a semicolon-terminated root list to libgap, opens a GAP output stream
    /// backed by a mutable GAP string, and caches the GAP globals used by other
    /// wrapper methods.
    ///
    /// Some package managers split GAP's core files and package files across
    /// sibling roots. When that layout is detected, additional package roots are
    /// included in the `-l` argument so GAP packages remain discoverable.
    pub fn try_init_with_root<P: AsRef<Path>>(root: P) -> Result<Gap> {
        let root = root.as_ref();
        validate_gap_root(root)?;

        let root_arg = gap_root_arg(root);
        let args = [
            CString::new("gap").context("Unable to build GAP argv[0]")?,
            CString::new("-l").context("Unable to build GAP -l argument")?,
            CString::new(root_arg).context("GAP root contains an interior NUL byte")?,
            CString::new("-q").context("Unable to build GAP -q argument")?,
            CString::new("-E").context("Unable to build GAP -E argument")?,
            CString::new("--nointeract").context("Unable to build GAP --nointeract argument")?,
            CString::new("-x").context("Unable to build GAP -x argument")?,
            CString::new("4096").context("Unable to build GAP line width argument")?,
        ];

        let mut c_args: Vec<*mut c_char> = args
            .iter()
            .map(|arg| arg.as_ptr() as *mut c_char)
            .chain(std::iter::once(ptr::null_mut()))
            .collect();

        GAP_ERROR_OCCURRED.store(false, Ordering::SeqCst);
        unsafe {
            SYSGAP_Initialize(
                c_args.len() as c_int - 1,
                c_args.as_mut_ptr(),
                Some(mark_bag),
                Some(gap_error_callback),
                1,
            );
        }
        let _ = GAP_THREAD.set(thread::current().id());

        if GAP_ERROR_OCCURRED.swap(false, Ordering::SeqCst) {
            return Err(anyhow!(
                "GAP reported an error during initialization; check that GAP's root and package directories are complete"
            ));
        }

        let objects = protect(|| unsafe {
            let global = |name: &CStr| GAP_ValueGlobalVariable(name.as_ptr());
            let output_str_obj = NEW_STRING(0);
            let output_stream_handle =
                DoOperation2Args(global(c"OutputTextString"), output_str_obj, GAP_True);
            let opened = SYSGAP_OpenOutputStream(output_stream_handle) == 1;
            let objects = [
                global(c"PrintTo"),
                global(c"InputTextString"),
                global(c"CallFuncList"),
                output_str_obj,
                output_stream_handle,
            ];
            (objects, opened)
        });
        let (objects, opened) = objects.context("GAP raised an error while setting up gap-sys")?;
        if !opened {
            return Err(anyhow!("Unable to open GAP output stream"));
        }
        let [print_fn, input_stream, call_func_list, output_str_obj, output_stream_handle] =
            objects;
        let gap = Gap {
            print_fn,
            input_stream,
            call_func_list,
            output_str_obj,
            output_stream_handle,
        };
        for obj in gap.cached_objects() {
            root_obj(obj);
        }
        Ok(gap)
    }

    /// Returns the GAP objects cached in this `Gap`, which it keeps rooted.
    fn cached_objects(&self) -> [Obj; 5] {
        [
            self.print_fn,
            self.input_stream,
            self.call_func_list,
            self.output_str_obj,
            self.output_stream_handle,
        ]
    }

    /// Evaluates GAP source text and returns a GC-rooted result.
    ///
    /// `cmd` is parsed by GAP's ordinary command reader through an
    /// `InputTextString`. The returned [`GapValue`] can safely survive later
    /// GAP calls and can be stored in Rust data structures.
    ///
    /// If `cmd` contains several statements, all of them are executed and the
    /// value of the last one is returned. It is an error if any statement
    /// fails or if `cmd` contains no statement. If the last statement produces
    /// no value (as, for example, a call to `Print` does), the result wraps a
    /// null `Obj`; it must not be passed back to GAP.
    ///
    /// # Panics
    ///
    /// Panics if `cmd` contains an interior NUL byte, because GAP receives it as
    /// a C string.
    pub fn eval(&self, cmd: &str) -> Result<GapValue> {
        Ok(self.root(self.eval_unrooted(cmd)?))
    }

    /// Evaluates GAP source text and returns an unrooted result.
    ///
    /// This is an advanced API. The returned [`GapRef`] may become invalid
    /// after any GAP operation that allocates. Prefer [`Gap::eval`].
    pub fn eval_unrooted(&self, cmd: &str) -> Result<GapRef> {
        /// What `READ_ALL_COMMANDS` reported for the statements in `cmd`.
        #[derive(Clone, Copy)]
        enum Outcome {
            Value(Obj),
            NoStatements,
            Failed(usize),
        }

        let c_cmd = CString::new(cmd).unwrap();
        let cmd_ptr = c_cmd.as_ptr();
        let input_stream = self.input_stream;
        // READ_ALL_COMMANDS returns one `[success, value, ...]` list per
        // statement. It catches errors itself and restores GAP's interpreter
        // and input state, so no error escapes to `protect`.
        let outcome = protect(|| unsafe {
            let instream = DoOperation1Args(input_stream, MakeString(cmd_ptr));
            let results = READ_ALL_COMMANDS(instream, GAP_False, GAP_False, GAP_False);
            let count = if GAP_IsList(results) != 0 {
                GAP_LenList(results)
            } else {
                0
            };
            let mut value = ptr::null_mut();
            for statement in 1..=count {
                let result = GAP_ElmList(results, statement);
                if GAP_ElmList(result, 1) != GAP_True {
                    return Outcome::Failed(statement);
                }
                value = GAP_ElmList(result, 2);
            }
            match count {
                0 => Outcome::NoStatements,
                _ => Outcome::Value(value),
            }
        })
        .context("GAP raised an error while evaluating a command")?;

        match outcome {
            Outcome::Value(obj) => Ok(GapRef { obj }),
            Outcome::NoStatements => Err(anyhow!("GAP command contained no statement")),
            Outcome::Failed(statement) => Err(anyhow!(
                "GAP reported an error evaluating statement {statement} of the command"
            )),
        }
    }

    /// Deprecated alias for [`Gap::eval`].
    #[deprecated(since = "0.2.4", note = "renamed to `eval`")]
    pub fn eval_rooted(&self, cmd: &str) -> Result<GapValue> {
        self.eval(cmd)
    }

    /// Renders a GAP object with GAP's `PrintTo` and returns the resulting text.
    ///
    /// The wrapper reuses an internal GAP string as the output buffer, which is
    /// why this method takes `&mut self`.
    ///
    /// # Panics
    ///
    /// Panics if GAP raises an error while printing the value. Use
    /// [`Gap::try_display`] to handle that case.
    pub fn display(&mut self, value: &GapValue) -> String {
        self.display_unrooted(value.as_unrooted())
    }

    /// Renders a GAP object with GAP's `PrintTo`, reporting GAP errors.
    pub fn try_display(&mut self, value: &GapValue) -> Result<String> {
        self.try_display_unrooted(value.as_unrooted())
    }

    /// Renders an unrooted GAP handle.
    ///
    /// The handle must be valid when this is called. Prefer [`Gap::display`].
    ///
    /// # Panics
    ///
    /// Panics if GAP raises an error while printing the value.
    pub fn display_unrooted(&mut self, value: GapRef) -> String {
        self.try_display_unrooted(value)
            .unwrap_or_else(|err| panic!("{err:#}"))
    }

    /// Renders an unrooted GAP handle, reporting GAP errors.
    ///
    /// The handle must be valid when this is called. Prefer [`Gap::try_display`].
    pub fn try_display_unrooted(&mut self, value: GapRef) -> Result<String> {
        let inputs = [value.obj];
        require_objects(&inputs)?;
        let _roots = TempRoots::new(&inputs);
        let (print_fn, stream, buffer) = (
            self.print_fn,
            self.output_stream_handle,
            self.output_str_obj,
        );
        let printed = protect(|| unsafe {
            // Discard anything GAP code printed since the last render.
            SET_LEN_STRING(buffer, 0);
            let succeeded = call_with_catch(print_fn, &[stream, value.obj]).is_some();
            (succeeded, GAP_CSTR_STRING(buffer), GAP_LenString(buffer))
        })
        .context("GAP raised an error while printing a value")?;

        let (succeeded, text, len) = printed;
        // SAFETY: GAP has not run since `protect` returned, so the buffer has
        // neither moved nor changed.
        let copy = unsafe {
            let text =
                String::from_utf8_lossy(std::slice::from_raw_parts(text.cast(), len)).into_owned();
            SET_LEN_STRING(buffer, 0);
            text
        };
        if succeeded {
            Ok(copy)
        } else {
            Err(anyhow!("GAP reported an error while printing a value"))
        }
    }

    /// Deprecated alias for [`Gap::display_unrooted`].
    #[deprecated(since = "0.2.4", note = "renamed to `display_unrooted`")]
    pub fn elem_string(&mut self, value: &GapRef) -> String {
        self.display_unrooted(*value)
    }

    /// Returns a GC-rooted value from a GAP list using a zero-based Rust index.
    ///
    /// GAP lists are one-based, so `idx` is incremented before calling into
    /// libgap.
    pub fn list_get(&self, list: &GapValue, idx: usize) -> Result<GapValue> {
        Ok(self.root(self.list_get_unrooted(list.as_unrooted(), idx)?))
    }

    /// Returns an unrooted value from a GAP list using a zero-based Rust index.
    ///
    /// This is an advanced API. Prefer [`Gap::list_get`].
    pub fn list_get_unrooted(&self, list: GapRef, idx: usize) -> Result<GapRef> {
        let inputs = [list.obj];
        require_objects(&inputs)?;
        let _roots = TempRoots::new(&inputs);
        let position = idx
            .checked_add(1)
            .ok_or_else(|| anyhow!("list index {idx} is out of range"))?;
        let element = protect(|| unsafe {
            (GAP_IsList(list.obj) != 0).then(|| GAP_ElmList(list.obj, position))
        })
        .context("GAP raised an error while reading a list element")?;
        match element {
            None => Err(anyhow!("GAP object is not a list")),
            Some(obj) if obj.is_null() => {
                Err(anyhow!("GAP list has no element at zero-based index {idx}"))
            }
            Some(obj) => Ok(GapRef { obj }),
        }
    }

    /// Deprecated alias for [`Gap::list_get_unrooted`].
    #[deprecated(since = "0.2.4", note = "renamed to `list_get_unrooted`")]
    pub fn get_list_elem(&self, list: &GapRef, idx: usize) -> Result<GapRef> {
        self.list_get_unrooted(*list, idx)
    }

    /// Roots an unrooted GAP handle and returns an owned value.
    ///
    /// The root is independent of `self`; `self` is present to keep the API
    /// tied to an initialized GAP runtime.
    pub fn root(&self, reference: GapRef) -> GapValue {
        GapValue::new(reference)
    }

    /// Looks up a GAP global variable by name.
    ///
    /// The returned value is rooted and can be retained across later GAP calls.
    pub fn get_global(&self, name: &str) -> Result<GapValue> {
        Ok(self.root(self.get_global_unrooted(name)?))
    }

    /// Looks up a GAP global variable by name without rooting it.
    ///
    /// This is an advanced API. Prefer [`Gap::get_global`].
    pub fn get_global_unrooted(&self, name: &str) -> Result<GapRef> {
        let c_name =
            CString::new(name).context("GAP global variable name contains an interior NUL byte")?;
        let name_ptr = c_name.as_ptr();
        let obj = protect(|| unsafe { GAP_ValueGlobalVariable(name_ptr) })
            .with_context(|| format!("GAP raised an error while looking up global `{name}`"))?;
        if obj.is_null() {
            return Err(anyhow!("GAP global variable `{name}` is not bound"));
        }
        Ok(GapRef { obj })
    }

    /// Deprecated alias for [`Gap::get_global_unrooted`].
    #[deprecated(since = "0.2.4", note = "renamed to `get_global_unrooted`")]
    pub fn global(&self, name: &str) -> Result<GapRef> {
        self.get_global_unrooted(name)
    }

    /// Calls a GAP function object with positional arguments.
    ///
    /// `function` must be a callable GAP value. The result is GC-rooted.
    ///
    /// If the function returns no value, the result wraps a null `Obj`; it
    /// must not be passed back to GAP.
    pub fn call(&self, function: &GapValue, args: &[&GapValue]) -> Result<GapValue> {
        let args = args.iter().map(|arg| arg.reference.obj).collect::<Vec<_>>();
        Ok(self.root(self.call_rooted_args(function.reference.obj, &args)?))
    }

    /// Calls a GAP function with unrooted handles and returns an unrooted handle.
    ///
    /// This is an advanced API. The handles must be valid when this is
    /// called; they are kept alive for the duration of the call. Prefer
    /// [`Gap::call`].
    pub fn call_unrooted(&self, function: GapRef, args: &[GapRef]) -> Result<GapRef> {
        let objs = std::iter::once(function.obj)
            .chain(args.iter().map(|arg| arg.obj))
            .collect::<Vec<_>>();
        let _roots = TempRoots::new(&objs);
        self.call_rooted_args(function.obj, &objs[1..])
    }

    /// Calls `function` on `args`, which the caller keeps rooted.
    ///
    /// GAP errors raised by the function are caught inside GAP with
    /// `CALL_WITH_CATCH`, which restores GAP's interpreter state.
    fn call_rooted_args(&self, function: Obj, args: &[Obj]) -> Result<GapRef> {
        require_objects(&[function])?;
        require_objects(args)?;
        let call_func_list = self.call_func_list;
        let result = protect(|| unsafe {
            if IS_FUNC(function) != 0 {
                call_with_catch(function, args)
            } else {
                // Callable non-functions, such as attribute-storing objects
                // with a `CallFuncList` method.
                let args = new_plist(args);
                call_with_catch(call_func_list, &[function, args])
            }
        })
        .context("GAP raised an error while calling a function")?;
        let obj =
            result.ok_or_else(|| anyhow!("GAP reported an error while calling a function"))?;
        Ok(GapRef { obj })
    }

    /// Deprecated alias for [`Gap::call_unrooted`].
    #[deprecated(since = "0.2.4", note = "renamed to `call_unrooted`")]
    pub fn call_function(&self, function: &GapRef, args: &[&GapRef]) -> Result<GapRef> {
        let args = args.iter().map(|arg| **arg).collect::<Vec<_>>();
        self.call_unrooted(*function, &args)
    }

    /// Looks up a GAP global function by name and calls it.
    ///
    /// This is a convenience wrapper around [`Gap::get_global`] and [`Gap::call`].
    pub fn call_global(&self, name: &str, args: &[&GapValue]) -> Result<GapValue> {
        let function = self.get_global(name)?;
        self.call(&function, args)
    }

    /// Calls a GAP global function without rooting its result.
    ///
    /// This is an advanced API. Prefer [`Gap::call_global`].
    pub fn call_global_unrooted(&self, name: &str, args: &[GapRef]) -> Result<GapRef> {
        let function = self.get_global_unrooted(name)?;
        self.call_unrooted(function, args)
    }

    /// Deprecated alias for [`Gap::get_global`].
    #[deprecated(since = "0.2.4", note = "renamed to `get_global`")]
    pub fn global_rooted(&self, name: &str) -> Result<GapValue> {
        self.get_global(name)
    }

    /// Deprecated alias for [`Gap::call_global`].
    #[deprecated(since = "0.2.4", note = "renamed to `call_global`")]
    pub fn call_global_rooted(&self, name: &str, args: &[&GapRef]) -> Result<GapValue> {
        let args = args.iter().map(|arg| self.root(**arg)).collect::<Vec<_>>();
        self.call_global(name, &args.iter().collect::<Vec<_>>())
    }

    /// Converts a Rust signed integer into GAP's immediate integer format.
    ///
    /// GAP small integers are encoded directly in the `Obj` word. The returned
    /// value does not need GC rooting because it is immediate.
    pub fn int(&self, value: isize) -> GapValue {
        self.root(self.int_unrooted(value))
    }

    /// Converts a Rust signed integer into an unrooted GAP immediate integer.
    pub fn int_unrooted(&self, value: isize) -> GapRef {
        GapRef {
            obj: unsafe { INTOBJ_INT(value as Int) },
        }
    }

    /// Converts a GAP integer object into a Rust `usize`.
    ///
    /// Returns an error if `value` is not an integer, is negative, or does not
    /// fit in a machine word.
    pub fn to_usize(&self, value: &GapValue) -> Result<usize> {
        self.to_usize_unrooted(value.as_unrooted())
    }

    /// Converts an unrooted GAP integer into a Rust `usize`.
    pub fn to_usize_unrooted(&self, value: GapRef) -> Result<usize> {
        require_objects(&[value.obj])?;
        let value =
            protect(|| unsafe { (GAP_IsInt(value.obj) != 0).then(|| Int_ObjInt(value.obj)) })
                .context("GAP raised an error while converting an integer")?
                .ok_or_else(|| anyhow!("GAP object is not an integer"))?;
        if value < 0 {
            return Err(anyhow!(
                "GAP integer {value} cannot be represented as usize"
            ));
        }
        Ok(value as usize)
    }

    /// Deprecated alias for [`Gap::to_usize_unrooted`].
    #[deprecated(since = "0.2.4", note = "renamed to `to_usize`")]
    pub fn integer_usize(&self, value: &GapRef) -> Result<usize> {
        self.to_usize_unrooted(*value)
    }

    /// Converts GAP's `true` and `false` objects into a Rust `bool`.
    ///
    /// Returns an error for any non-boolean GAP object.
    pub fn to_bool(&self, value: &GapValue) -> Result<bool> {
        self.to_bool_unrooted(value.as_unrooted())
    }

    /// Converts an unrooted GAP boolean into a Rust `bool`.
    pub fn to_bool_unrooted(&self, value: GapRef) -> Result<bool> {
        unsafe {
            if value.obj == GAP_True {
                Ok(true)
            } else if value.obj == GAP_False {
                Ok(false)
            } else {
                Err(anyhow!("GAP object is not a boolean"))
            }
        }
    }

    /// Deprecated alias for [`Gap::to_bool_unrooted`].
    #[deprecated(since = "0.2.4", note = "renamed to `to_bool`")]
    pub fn boolean(&self, value: &GapRef) -> Result<bool> {
        self.to_bool_unrooted(*value)
    }

    /// Returns whether `element` is GAP's distinguished `fail` value.
    pub fn is_fail(&self, value: &GapValue) -> bool {
        self.is_fail_unrooted(value.as_unrooted())
    }

    /// Returns whether an unrooted handle is GAP's distinguished `fail` value.
    pub fn is_fail_unrooted(&self, value: GapRef) -> bool {
        unsafe { value.obj == GAP_Fail || value.obj == Fail }
    }

    /// Builds a GC-rooted mutable GAP plain list from already-created values.
    ///
    /// GAP lists are one-based, so each Rust slice element is written at
    /// position `idx + 1`.
    pub fn list(&self, elements: &[GapValue]) -> GapValue {
        let elements = elements
            .iter()
            .map(|element| element.reference.obj)
            .collect::<Vec<_>>();
        self.root(GapRef {
            obj: expect_no_gap_error(protect(|| unsafe { new_plist(&elements) })),
        })
    }

    /// Builds an unrooted mutable GAP plain list from unrooted handles.
    ///
    /// This is an advanced API. The handles must be valid when this is
    /// called. Prefer [`Gap::list`].
    pub fn list_unrooted(&self, elements: &[GapRef]) -> GapRef {
        let elements = elements
            .iter()
            .map(|element| element.obj)
            .collect::<Vec<_>>();
        let _roots = TempRoots::new(&elements);
        GapRef {
            obj: expect_no_gap_error(protect(|| unsafe { new_plist(&elements) })),
        }
    }

    /// Deprecated alias for [`Gap::list`].
    #[deprecated(since = "0.2.4", note = "renamed to `list`")]
    pub fn list_rooted(&self, elements: &[GapRef]) -> GapValue {
        self.root(self.list_unrooted(elements))
    }

    /// Returns the length of a GAP list.
    ///
    /// # Panics
    ///
    /// Panics if `list` is not a list, or if GAP raises an error computing
    /// its length.
    pub fn list_len(&self, list: &GapValue) -> usize {
        self.list_len_unrooted(list.as_unrooted())
    }

    /// Returns the length of a list referenced by an unrooted handle.
    ///
    /// # Panics
    ///
    /// Panics if `list` is not a list, or if GAP raises an error computing
    /// its length.
    pub fn list_len_unrooted(&self, list: GapRef) -> usize {
        let inputs = [list.obj];
        expect_no_gap_error(require_objects(&inputs));
        let _roots = TempRoots::new(&inputs);
        let len = protect(|| unsafe { (GAP_IsList(list.obj) != 0).then(|| LEN_LIST(list.obj)) });
        expect_no_gap_error(len).expect("GAP object is not a list") as usize
    }

    /// Builds a GAP permutation from zero-based images.
    ///
    /// `images[i]` is interpreted as the zero-based image of the point `i`.
    /// GAP's permutation constructors are one-based, so both source and target
    /// lists are shifted by one before calling `MappingPermListList`.
    ///
    /// Temporary lists are rooted around the GAP call because constructing the
    /// permutation can allocate.
    pub fn permutation_from_zero_based_images(&self, images: &[usize]) -> Result<GapValue> {
        let source = (1..=images.len())
            .map(|idx| self.int(idx as isize))
            .collect::<Vec<_>>();
        let target = images
            .iter()
            .map(|&image| self.int(image as isize + 1))
            .collect::<Vec<_>>();
        let source = self.list(&source);
        let target = self.list(&target);
        self.call_global("MappingPermListList", &[&source, &target])
    }

    /// Deprecated alias for [`Gap::permutation_from_zero_based_images`].
    #[deprecated(
        since = "0.2.4",
        note = "renamed to `permutation_from_zero_based_images`"
    )]
    pub fn permutation_from_zero_based_images_rooted(&self, images: &[usize]) -> Result<GapValue> {
        self.permutation_from_zero_based_images(images)
    }

    /// Computes zero-based images of a GAP permutation on `0..degree`.
    ///
    /// GAP's `OnPoints` action is evaluated on one-based points and each result
    /// is shifted back to Rust's zero-based convention.
    pub fn permutation_images_zero_based(
        &self,
        permutation: &GapValue,
        degree: usize,
    ) -> Result<Vec<usize>> {
        let on_points = self.get_global("OnPoints")?;
        (1..=degree)
            .map(|point| {
                let point = self.int(point as isize);
                let image = self.call(&on_points, &[&point, permutation])?;
                self.to_usize(&image).and_then(|image| {
                    image
                        .checked_sub(1)
                        .ok_or_else(|| anyhow!("permutation sent a point outside [1..degree]"))
                })
            })
            .collect()
    }

    /// Removes one manually-added GC root for an unrooted handle.
    ///
    /// This is the manual counterpart to [`Gap::root_ref`]. Prefer [`GapValue`] for
    /// ordinary ownership because it releases roots automatically on drop.
    pub fn unroot_ref(&self, reference: GapRef) {
        unroot_obj(reference.obj);
    }

    /// Deprecated alias for [`Gap::unroot_ref`].
    #[deprecated(since = "0.2.4", note = "renamed to `unroot_ref`")]
    pub fn free(&self, value: &GapRef) {
        self.unroot_ref(*value);
    }

    /// Adds a GC root for `obj`.
    ///
    /// Each call should be paired with [`Gap::unroot_ref`] unless ownership is handed
    /// to a [`GapValue`]. Rooting is required for non-immediate GAP objects that
    /// outlive the GAP call that produced them.
    pub fn root_ref(&self, reference: GapRef) {
        root_obj(reference.obj);
    }

    /// Deprecated alias for [`Gap::root_ref`].
    #[deprecated(since = "0.2.4", note = "renamed to `root_ref`")]
    pub fn alloc(&self, value: &GapRef) {
        self.root_ref(*value);
    }
}

/// Ensures the process-global GAP runtime has been initialized.
///
/// Initialization is protected by `GLOBAL_GAP_INIT` so racing callers either
/// observe an existing runtime or exactly one of them creates it.
fn ensure_global() -> Result<()> {
    if GLOBAL_GAP.get().is_some() {
        return Ok(());
    }

    let _init_guard = GLOBAL_GAP_INIT
        .lock()
        .map_err(|_| anyhow!("global GAP initialization mutex was poisoned"))?;
    if GLOBAL_GAP.get().is_none() {
        let gap = Gap::try_init()?;
        GLOBAL_GAP
            .set(Mutex::new(gap))
            .map_err(|_| anyhow!("global GAP runtime is already initialized"))?;
    }
    Ok(())
}

/// Runs `body`, which calls into libgap, inside `GAP_Enter()`/`GAP_Leave()`.
///
/// Every libgap call that can allocate, run GAP code, or raise a GAP error
/// must go through this function. (Pure accessors such as reading a string's
/// bytes are exempt.) It does three things:
///
/// - It points GASMAN's conservative stack scan at the current thread and at
///   a stack frame that outlives `body`, so GAP objects held in `body`'s
///   locals survive a garbage collection, whichever thread is calling.
/// - It gives GAP errors that nothing inside GAP handles a place to return to,
///   and restores GAP's interpreter state afterwards. Such an error is
///   reported as `Err`. Wrapper methods catch the errors they expect inside
///   GAP (`READ_ALL_COMMANDS`, `CALL_WITH_CATCH`), so this is a backstop.
/// - It clears the flag set by GAP's error callback, so that the flag only
///   ever describes the current call.
///
/// Calls must not nest, and the caller must hold the GAP runtime (for the
/// global runtime, a [`GlobalGapGuard`]).
///
/// After a GAP error, `body` is abandoned by a `longjmp`, which skips its
/// remaining code and any destructors. `body` must therefore only make FFI
/// calls and handle `Copy` data, and must not panic. Requiring `F: Copy` and
/// `R: Copy` rules out captured values and results with destructors; `body`
/// must not create any either.
fn protect<F, R>(body: F) -> Result<R>
where
    F: FnOnce() -> R + Copy,
    R: Copy,
{
    /// The data `SYSGAP_Run` passes back to `trampoline`.
    struct Call<F, R> {
        body: F,
        result: Option<R>,
    }

    unsafe extern "C" fn trampoline<F, R>(data: *mut c_void)
    where
        F: FnOnce() -> R + Copy,
        R: Copy,
    {
        let call = &mut *data.cast::<Call<F, R>>();
        call.result = Some((call.body)());
    }

    check_gap_thread();
    GAP_ERROR_OCCURRED.store(false, Ordering::SeqCst);
    let mut call = Call { body, result: None };
    let completed = unsafe {
        SYSGAP_Run(
            Some(trampoline::<F, R>),
            (&mut call as *mut Call<F, R>).cast(),
        )
    };
    match call.result {
        Some(result) if completed != 0 => Ok(result),
        _ => Err(anyhow!(
            "GAP raised an error that was not caught; see GAP's error output for details"
        )),
    }
}

/// Panics with the error from a [`protect`] call in an infallible method.
///
/// Only uncaught GAP errors reach this, and the wrapper only calls it where
/// such errors indicate a bug or misuse, never for ordinary failures.
fn expect_no_gap_error<R>(result: Result<R>) -> R {
    result.unwrap_or_else(|err| panic!("{err:#}"))
}

/// Panics if GAP lacks `GAP_Enter()` and is used off its initializing thread.
///
/// Without `GAP_Enter()` there is no supported way to tell GASMAN which stack
/// to scan, so it keeps scanning the stack of the thread that called
/// `GAP_Initialize`. Calling GAP from any other thread can then free live
/// objects or read unmapped memory.
fn check_gap_thread() {
    if SYSGAP_HAS_ENTER != 0 {
        return;
    }
    if let Some(gap_thread) = GAP_THREAD.get() {
        if *gap_thread != thread::current().id() {
            panic!(
                "this GAP release has no GAP_Enter() (GAP < 4.11), so it can only be \
                 used from the thread that initialized it"
            );
        }
    }
}

/// Rejects null objects before they reach GAP, which would dereference them.
///
/// The wrapper represents "no value" (from a statement or function that
/// returns nothing) as a null `Obj`.
fn require_objects(objs: &[Obj]) -> Result<()> {
    if objs.iter().any(|obj| obj.is_null()) {
        Err(anyhow!(
            "a GAP value holds no object (it came from a statement or function \
             that returned nothing), so it cannot be passed to GAP"
        ))
    } else {
        Ok(())
    }
}

/// Builds a mutable GAP plain list holding `elements`.
///
/// # Safety
///
/// Must run inside [`protect`], with every element rooted or immediate.
unsafe fn new_plist(elements: &[Obj]) -> Obj {
    let list = NEW_PLIST(TNUM_T_PLIST as UInt, elements.len() as Int);
    SET_LEN_PLIST(list, elements.len() as Int);
    for (idx, &element) in elements.iter().enumerate() {
        SET_ELM_PLIST(list, idx as Int + 1, element);
    }
    CHANGED_BAG(list);
    list
}

/// Calls the GAP function `function` on `args`, catching GAP errors in GAP.
///
/// Returns `None` if the call raised an error, and otherwise the returned
/// value, which is null if the function returned nothing. `CALL_WITH_CATCH`
/// restores GAP's interpreter state after an error.
///
/// # Safety
///
/// Must run inside [`protect`], with `function` (which must satisfy `IS_FUNC`)
/// and every argument rooted or immediate.
unsafe fn call_with_catch(function: Obj, args: &[Obj]) -> Option<Obj> {
    let result = CALL_WITH_CATCH(function, new_plist(args));
    (GAP_ElmList(result, 1) == GAP_True).then(|| GAP_ElmList(result, 2))
}

/// Returns the runtime GAP root selected by the environment or build script.
///
/// `GAP_SYS_ROOT` wins at runtime. Otherwise, `build.rs` injects the discovered
/// root into `GAP_SYS_GAP_ROOT`.
fn default_gap_root() -> PathBuf {
    std::env::var_os("GAP_SYS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("GAP_SYS_GAP_ROOT")))
}

/// Builds the semicolon-terminated value passed to GAP's `-l` option.
///
/// The first entry is always `root`. Additional inferred roots are appended
/// when they look like valid GAP runtime or package roots, which supports
/// package-manager layouts that split core files from packages.
fn gap_root_arg(root: &Path) -> String {
    let mut roots = Vec::new();
    push_unique_path(&mut roots, root.to_path_buf());

    for candidate in inferred_runtime_roots(root) {
        if is_gap_runtime_root(&candidate) {
            push_unique_path(&mut roots, candidate);
        }
    }

    let mut arg = roots
        .iter()
        .map(|root| root.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(";");
    arg.push(';');
    arg
}

/// Returns nearby candidate runtime roots for split GAP installations.
///
/// The search walks a small number of ancestors and looks for sibling
/// `lib/gap` and `share/gap` directories without probing all the way to the
/// filesystem root.
fn inferred_runtime_roots(root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    for base in root
        .ancestors()
        .take(4)
        .filter(|base| base.parent().is_some())
    {
        push_unique_path(&mut roots, base.join("lib").join("gap"));
        push_unique_path(&mut roots, base.join("share").join("gap"));
    }

    roots
}

/// Returns whether `root` looks useful in GAP's runtime root list.
///
/// A core root contains `lib/init.g`; a package-only root contains `pkg`.
fn is_gap_runtime_root(root: &Path) -> bool {
    root.join("lib").join("init.g").is_file() || root.join("pkg").is_dir()
}

/// Appends `path` if it has not already been seen.
fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

/// Checks that `root` contains the core GAP initialization file.
fn validate_gap_root(root: &Path) -> Result<()> {
    if root.join("lib").join("init.g").is_file() {
        Ok(())
    } else {
        Err(anyhow!(
            "GAP root `{}` does not contain `lib/init.g`; set GAP_SYS_ROOT to a valid GAP root",
            root.display()
        ))
    }
}

/// Root counts for the GAP objects Rust holds, keyed by object address.
///
/// libgap calls `mark_bag` during garbage collection. That callback walks this
/// table and marks each object so GAP will not free it while Rust still holds
/// a rooted handle. The mutex makes it safe to change the table from any
/// thread, including while another thread is collecting garbage.
static OBJ_REFS: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
/// Lazily initialized process-global GAP runtime.
static GLOBAL_GAP: OnceLock<Mutex<Gap>> = OnceLock::new();
/// Initialization mutex used before `GLOBAL_GAP` has been set.
static GLOBAL_GAP_INIT: Mutex<()> = Mutex::new(());
/// The thread that called `GAP_Initialize`.
static GAP_THREAD: OnceLock<ThreadId> = OnceLock::new();
/// Flag set by GAP's error callback.
///
/// [`protect`] clears it before each call into libgap. Wrapper methods detect
/// errors from GAP's own results instead, because GAP code may raise and catch
/// errors internally; the flag is only consulted after initialization.
static GAP_ERROR_OCCURRED: AtomicBool = AtomicBool::new(false);

/// Locks the root table, ignoring poisoning (the table is always consistent).
fn obj_refs() -> MutexGuard<'static, BTreeMap<usize, usize>> {
    OBJ_REFS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Returns whether `obj` is a reference to a GAP bag.
///
/// Null and immediate objects (small integers and finite field elements,
/// tagged in the low two bits) need no rooting.
fn is_bag_ref(obj: Obj) -> bool {
    !obj.is_null() && (obj as usize) & 0b11 == 0
}

/// Adds a root for `obj` to the table used by GAP's garbage collector.
///
/// Roots are counted: adding the same object twice requires two matching
/// calls to `unroot_obj`.
fn root_obj(obj: Obj) {
    if is_bag_ref(obj) {
        *obj_refs().entry(obj as usize).or_insert(0) += 1;
    }
}

/// Removes one root for `obj`.
///
/// Missing roots are ignored, matching the historic behavior of the wrapper's
/// manual `alloc`/`free` API.
fn unroot_obj(obj: Obj) {
    let mut refs = obj_refs();
    if let Some(count) = refs.get_mut(&(obj as usize)) {
        *count -= 1;
        if *count == 0 {
            refs.remove(&(obj as usize));
        }
    }
}

/// Roots a set of objects for as long as the guard lives.
///
/// Used by the `*_unrooted` methods to keep their inputs alive while GAP
/// allocates.
struct TempRoots<'a> {
    /// The objects rooted by this guard.
    objs: &'a [Obj],
}

impl<'a> TempRoots<'a> {
    fn new(objs: &'a [Obj]) -> Self {
        for &obj in objs {
            root_obj(obj);
        }
        Self { objs }
    }
}

impl Drop for TempRoots<'_> {
    fn drop(&mut self) {
        for &obj in self.objs {
            unroot_obj(obj);
        }
    }
}

/// Records that GAP reported an error.
///
/// The callback is intentionally tiny because it is invoked from libgap's C
/// control flow. Rust code polls and clears the flag after individual calls.
///
/// # Safety
///
/// libgap must call this with the callback ABI registered in
/// `SYSGAP_Initialize`.
unsafe extern "C" fn gap_error_callback() {
    GAP_ERROR_OCCURRED.store(true, Ordering::SeqCst);
}

/// Marks every Rust-rooted GAP object during a GAP garbage collection.
///
/// This function is registered with libgap at initialization. It must not
/// allocate GAP objects or call back into high-level GAP code; it only forwards
/// each raw `Obj` to the version-compatible `SYSGAP_MarkBag` wrapper.
///
/// # Safety
///
/// libgap must call this only while its garbage collector is marking.
unsafe extern "C" fn mark_bag() {
    for &obj in obj_refs().keys() {
        SYSGAP_MarkBag(obj as Obj);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluation_and_scalar_conversions_cross_the_ffi_boundary() -> Result<()> {
        with_gap(|gap| {
            let integer = gap.eval("42;")?;
            let boolean = gap.eval("true;")?;
            let failure = gap.eval("fail;")?;
            let string = gap.eval("\"Hello from GAP\";")?;

            assert_eq!(gap.to_usize(&integer)?, 42);
            assert!(gap.to_bool(&boolean)?);
            assert!(gap.is_fail(&failure));
            assert_eq!(gap.display(&string), "Hello from GAP");
            Ok(())
        })
    }

    #[test]
    fn top_level_evaluation_keeps_results_alive_across_gap_calls() -> Result<()> {
        let value = eval("[1, 2, 3];")?;
        with_gap(|gap| {
            for _ in 0..100 {
                gap.eval("List([1..100], x -> x^2);")?;
            }
            assert_eq!(gap.list_len(&value), 3);
            assert_eq!(gap.to_usize(&gap.list_get(&value, 2)?)?, 3);
            Ok(())
        })
    }

    #[test]
    fn global_calls_and_collection_helpers_round_trip_values() -> Result<()> {
        with_gap(|gap| {
            let elements = [gap.int(2), gap.int(4), gap.int(6)];
            let list = gap.list(&elements);
            let length = gap.call_global("Length", &[&list])?;

            assert_eq!(gap.to_usize(&length)?, 3);
            assert_eq!(gap.to_usize(&gap.list_get(&list, 1)?)?, 4);

            let permutation = gap.permutation_from_zero_based_images(&[2, 0, 1])?;
            assert_eq!(
                gap.permutation_images_zero_based(&permutation, 3)?,
                vec![2, 0, 1]
            );
            Ok(())
        })
    }

    #[test]
    fn runtime_initialization_makes_standard_gap_packages_available() -> Result<()> {
        with_gap(|gap| {
            let gapdoc = gap.eval("LoadPackage(\"gapdoc\");")?;
            if !gap.to_bool(&gapdoc).unwrap_or(false) {
                let roots = gap.eval("GAPInfo.RootPaths;")?;
                let root_paths = gap.display(&roots);
                panic!("unable to load GAP package gapdoc; GAPInfo.RootPaths = {root_paths}");
            }
            Ok(())
        })
    }

    #[test]
    fn runtime_root_arg_includes_homebrew_split_package_root() {
        let base = temp_root("homebrew-split-runtime");
        let root = base.join("lib/gap");
        let package_root = base.join("share/gap");
        write_file(root.join("lib/init.g"));
        write_file(package_root.join("pkg/gapdoc/PackageInfo.g"));

        let arg = gap_root_arg(&root);

        assert!(arg.contains(&format!("{};", root.display())));
        assert!(arg.contains(&format!("{};", package_root.display())));
    }

    #[test]
    fn runtime_root_arg_leaves_unsplit_root_alone() {
        let root = temp_root("unsplit-runtime");
        write_file(root.join("lib/init.g"));
        write_file(root.join("pkg/gapdoc/PackageInfo.g"));

        assert_eq!(gap_root_arg(&root), format!("{};", root.display()));
    }

    fn temp_root(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gap-sys-runtime-{name}-{unique}"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_file(path: PathBuf) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }
}
