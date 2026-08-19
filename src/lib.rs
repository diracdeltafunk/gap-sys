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

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use anyhow::{anyhow, Context, Result};
use std::ffi::{c_char, c_int, CStr, CString};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// A live libgap interpreter instance.
///
/// `Gap` caches a handful of GAP globals and stream objects needed by the
/// wrapper methods. libgap itself is process-global and not generally designed
/// for independent parallel runtimes, so callers should prefer [`global`] or
/// [`with_gap`] when sharing one interpreter across a program.
pub struct Gap {
    /// GAP's `PrintTo` function, cached as a raw GAP object for rendering.
    print_fn: Obj,
    /// GAP's `InputTextString` operation, used to feed strings to the reader.
    input_stream: Obj,
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
        unsafe {
            SYSGAP_CloseOutput();
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

impl Clone for GapValue {
    fn clone(&self) -> Self {
        root_obj(&self.reference);
        Self {
            reference: self.reference,
        }
    }
}

impl Drop for GapValue {
    fn drop(&mut self) {
        unroot_obj(&self.reference);
    }
}

impl GapValue {
    /// Roots `reference` and returns an owned GAP value.
    ///
    /// The root is released when the returned `GapValue` is dropped.
    fn new(reference: GapRef) -> Self {
        root_obj(&reference);
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
        let args = vec![
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

        unsafe {
            OBJ_REFS = Box::into_raw(Box::default());
            GAP_ERROR_OCCURRED.store(false, Ordering::SeqCst);

            SYSGAP_Initialize(
                c_args.len() as c_int - 1,
                c_args.as_mut_ptr(),
                Some(mark_bag),
                Some(gap_error_callback),
                1,
            );
        }

        if GAP_ERROR_OCCURRED.swap(false, Ordering::SeqCst) {
            return Err(anyhow!(
                "GAP reported an error during initialization; check that GAP's root and package directories are complete"
            ));
        }

        let output_text_str_operation = unsafe {
            let raw_ptr = CString::new("OutputTextString").unwrap().into_raw();
            let obj = ValGVar(GVarName(raw_ptr));
            let _ = CString::from_raw(raw_ptr);
            obj
        };

        let (output_str_obj, output_stream_handle) = unsafe {
            let output_str_obj = NEW_STRING(0);
            let handle_obj = DoOperation2Args(output_text_str_operation, output_str_obj, GAP_True);
            if SYSGAP_OpenOutputStream(handle_obj) != 1 {
                return Err(anyhow!("Unable to open GAP output stream"));
            }
            (output_str_obj, handle_obj)
        };

        let print_fn = unsafe {
            let raw_ptr = CString::new("PrintTo").unwrap().into_raw();
            let obj = GAP_ValueGlobalVariable(raw_ptr);
            let _ = CString::from_raw(raw_ptr);
            obj
        };

        let input_stream = unsafe {
            let raw_ptr = CString::new("InputTextString").unwrap().into_raw();
            let obj = GAP_ValueGlobalVariable(raw_ptr);
            let _ = CString::from_raw(raw_ptr);
            obj
        };

        Ok(Gap {
            print_fn,
            input_stream,
            output_str_obj,
            output_stream_handle,
        })
    }

    /// Evaluates GAP source text and returns a GC-rooted result.
    ///
    /// `cmd` is parsed by GAP's ordinary command reader through an
    /// `InputTextString`. The returned [`GapValue`] can safely survive later
    /// GAP calls and can be stored in Rust data structures.
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
        let c_cmd = CString::new(cmd).unwrap();

        unsafe {
            // Create a raw pointer to the CString, needs to be freed later
            let raw_ptr = c_cmd.into_raw();
            let instream = DoOperation1Args(self.input_stream, MakeString(raw_ptr));
            let obj = READ_ALL_COMMANDS(instream, GAP_False, GAP_False, GAP_False);
            // Drop the CString so it doesn't leak
            let _ = CString::from_raw(raw_ptr);

            let obj = GAP_ElmList(obj, 1);
            let success = GAP_ElmList(obj, 1);

            if success == GAP_True {
                let obj = GAP_ElmList(obj, 2);
                Ok(GapRef { obj })
            } else {
                Err(anyhow::anyhow!("Error evaluating command"))
            }
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
    pub fn display(&mut self, value: &GapValue) -> String {
        self.display_unrooted(value.as_unrooted())
    }

    /// Renders an unrooted GAP handle.
    ///
    /// The handle must remain valid for this call. Prefer [`Gap::display`].
    pub fn display_unrooted(&mut self, value: GapRef) -> String {
        unsafe {
            SYSGAP_CallFunc2Args(self.print_fn, self.output_stream_handle, value.obj);
        }

        let cstr: &CStr = unsafe { CStr::from_ptr(GAP_CSTR_STRING(self.output_str_obj)) };
        let copy = cstr.to_string_lossy().to_string();

        unsafe {
            SET_LEN_STRING(self.output_str_obj, 0);
        }

        copy
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
        unsafe {
            let obj = GAP_ElmList(list.obj, idx + 1);
            Ok(GapRef { obj })
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
        let raw_ptr = CString::new(name)
            .context("GAP global variable name contains an interior NUL byte")?
            .into_raw();
        let obj = unsafe { GAP_ValueGlobalVariable(raw_ptr) };
        unsafe {
            let _ = CString::from_raw(raw_ptr);
        }
        check_gap_error("looking up a global variable")?;
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
    pub fn call(&self, function: &GapValue, args: &[&GapValue]) -> Result<GapValue> {
        let function = function.as_unrooted();
        let args = args.iter().map(|arg| arg.as_unrooted()).collect::<Vec<_>>();
        Ok(self.root(self.call_unrooted(function, &args)?))
    }

    /// Calls a GAP function with unrooted handles and returns an unrooted handle.
    ///
    /// This is an advanced API. Prefer [`Gap::call`].
    pub fn call_unrooted(&self, function: GapRef, args: &[GapRef]) -> Result<GapRef> {
        let mut raw_args = args.iter().map(|arg| arg.obj).collect::<Vec<_>>();
        GAP_ERROR_OCCURRED.store(false, Ordering::SeqCst);
        let obj = unsafe {
            GAP_CallFuncArray(function.obj, raw_args.len() as UInt, raw_args.as_mut_ptr())
        };
        check_gap_error("calling a GAP function")?;
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
    /// Returns an error if GAP produces a negative integer. The current
    /// implementation uses libgap's small-integer conversion and is intended for
    /// values known to fit in GAP's immediate integer representation.
    pub fn to_usize(&self, value: &GapValue) -> Result<usize> {
        self.to_usize_unrooted(value.as_unrooted())
    }

    /// Converts an unrooted GAP integer into a Rust `usize`.
    pub fn to_usize_unrooted(&self, value: GapRef) -> Result<usize> {
        let value = unsafe { Int_ObjInt(value.obj) };
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
            .map(|element| element.as_unrooted())
            .collect::<Vec<_>>();
        self.root(self.list_unrooted(&elements))
    }

    /// Builds an unrooted mutable GAP plain list from unrooted handles.
    ///
    /// This is an advanced API. Prefer [`Gap::list`].
    pub fn list_unrooted(&self, elements: &[GapRef]) -> GapRef {
        unsafe {
            let list = NEW_PLIST(TNUM_T_PLIST as UInt, elements.len() as Int);
            SET_LEN_PLIST(list, elements.len() as Int);
            for (idx, element) in elements.iter().enumerate() {
                SET_ELM_PLIST(list, idx as Int + 1, element.obj);
            }
            CHANGED_BAG(list);
            GapRef { obj: list }
        }
    }

    /// Deprecated alias for [`Gap::list`].
    #[deprecated(since = "0.2.4", note = "renamed to `list`")]
    pub fn list_rooted(&self, elements: &[GapRef]) -> GapValue {
        self.root(self.list_unrooted(elements))
    }

    /// Returns the length of a GAP list.
    pub fn list_len(&self, list: &GapValue) -> usize {
        self.list_len_unrooted(list.as_unrooted())
    }

    /// Returns the length of a list referenced by an unrooted handle.
    pub fn list_len_unrooted(&self, list: GapRef) -> usize {
        unsafe { LEN_LIST(list.obj) as usize }
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
        unroot_obj(&reference);
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
        root_obj(&reference);
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

/// Converts the asynchronous GAP error flag into a contextual Rust error.
///
/// libgap reports some failures through the callback registered at
/// initialization time. The callback can only flip a flag, so this helper is
/// called immediately after operations that may have raised a GAP error.
fn check_gap_error(context: &str) -> Result<()> {
    if GAP_ERROR_OCCURRED.swap(false, Ordering::SeqCst) {
        Err(anyhow!("GAP reported an error while {context}"))
    } else {
        Ok(())
    }
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

/// Table of Rust-held GAP object roots.
///
/// libgap calls `mark_bag` during garbage collection. That callback walks this
/// table and marks each object so GAP will not move or free it while Rust still
/// holds a rooted handle.
static mut OBJ_REFS: *mut Vec<GapRef> = ptr::null_mut();
/// Mutex protecting `OBJ_REFS` from concurrent mutation and marking.
static OBJ_REFS_LOCK: Mutex<()> = Mutex::new(());
/// Lazily initialized process-global GAP runtime.
static GLOBAL_GAP: OnceLock<Mutex<Gap>> = OnceLock::new();
/// Initialization mutex used before `GLOBAL_GAP` has been set.
static GLOBAL_GAP_INIT: Mutex<()> = Mutex::new(());
/// Sticky flag set by GAP's error callback and consumed by `check_gap_error`.
static GAP_ERROR_OCCURRED: AtomicBool = AtomicBool::new(false);

/// Adds `obj` to the Rust root table used by GAP's garbage collector.
///
/// Roots are counted by entry rather than by pointer identity: adding the same
/// object twice requires two matching calls to `unroot_obj`.
fn root_obj(obj: &GapRef) {
    let _guard = OBJ_REFS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    unsafe {
        OBJ_REFS
            .as_mut()
            .expect("GAP object rooting is only available after GAP initialization")
            .push(*obj);
    }
}

/// Removes one matching root-table entry for `obj`.
///
/// Missing roots are ignored, matching the historic behavior of the wrapper's
/// manual `alloc`/`free` API.
fn unroot_obj(obj: &GapRef) {
    let _guard = OBJ_REFS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    unsafe {
        let refs = OBJ_REFS
            .as_mut()
            .expect("GAP object rooting is only available after GAP initialization");
        if let Some(idx) = refs.iter().position(|x| x.obj == obj.obj) {
            refs.remove(idx);
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
/// libgap must call this only while its garbage collector is marking and after
/// `OBJ_REFS` has been initialized.
unsafe extern "C" fn mark_bag() {
    let _guard = OBJ_REFS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for o in &*OBJ_REFS {
        SYSGAP_MarkBag(o.obj);
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
