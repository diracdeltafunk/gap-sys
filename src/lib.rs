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
//! GAP owns every `Obj`. A [`GapElement`] is only a lightweight handle to that
//! object; use [`GapObj`] or [`Gap::alloc`] when a handle must survive calls
//! that may allocate and trigger the GAP garbage collector.

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

/// A borrowed handle to a GAP object.
///
/// This is a copyable Rust-side wrapper around GAP's raw `Obj` pointer. It does
/// not root the object with GAP's garbage collector. If the object needs to
/// remain valid across any operation that can allocate in GAP, convert it into
/// a [`GapObj`] with [`Gap::root`] or explicitly call [`Gap::alloc`].
#[derive(Clone, Debug)]
pub struct GapElement {
    /// Raw GAP object pointer produced by libgap.
    ///
    /// The pointer is meaningful only while the libgap runtime is initialized
    /// and the object remains reachable or explicitly rooted.
    pub obj: Obj,
}

/// An owned, garbage-collector-rooted GAP object handle.
///
/// Cloning a `GapObj` adds another entry to the root table, and dropping it
/// removes one. This makes the wrapped GAP object safe to keep in Rust data
/// structures across GAP allocations.
#[derive(Debug)]
pub struct GapObj {
    /// The borrowed object handle that is registered in `OBJ_REFS`.
    element: GapElement,
}

/// Mutex guard for the process-global [`Gap`] runtime.
///
/// The guard dereferences to `Gap`, giving callers mutable access while keeping
/// all global interpreter use serialized.
pub struct GlobalGapGuard {
    /// The underlying lock guard held for the duration of the borrow.
    guard: MutexGuard<'static, Gap>,
}

impl fmt::Display for GapElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let cstr = CStr::from_ptr(GAP_CSTR_STRING(self.obj));
            write!(f, "{}", cstr.to_string_lossy())
        }
    }
}

impl fmt::Pointer for GapElement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:p}", self.obj)
    }
}

/// Parses a hexadecimal address string into a raw GAP bag pointer.
///
/// This exists for compatibility with older call sites that serialized GAP
/// object addresses as strings. New code should pass `GapElement` or `GapObj`
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

/// Converts a textual raw pointer address into a `GapElement`.
///
/// This is intended only for legacy pointer-string interop. It panics if `s`
/// is not a valid hexadecimal address.
impl From<&str> for GapElement {
    fn from(s: &str) -> Self {
        GapElement {
            obj: unsafe { hex_str_to_ptr(s.trim()).unwrap() },
        }
    }
}

impl Clone for GapObj {
    fn clone(&self) -> Self {
        root_obj(&self.element);
        Self {
            element: self.element.clone(),
        }
    }
}

impl Drop for GapObj {
    fn drop(&mut self) {
        unroot_obj(&self.element);
    }
}

impl GapObj {
    /// Roots `element` and returns an owned GAP object handle.
    ///
    /// The root is released when the returned `GapObj` is dropped.
    pub fn new(element: GapElement) -> Self {
        root_obj(&element);
        Self { element }
    }

    /// Returns the borrowed handle for calls that accept a [`GapElement`].
    ///
    /// The returned reference remains protected by this `GapObj`'s root.
    pub fn as_element(&self) -> &GapElement {
        &self.element
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

/// Evaluates GAP source text in the process-global runtime and roots the result.
///
/// This is shorthand for `global()?.eval_rooted(cmd)`. It is useful for small
/// programs and tests; use [`with_gap`] or [`global`] when several operations
/// should share one lock scope.
pub fn gap_eval(cmd: &str) -> Result<GapObj> {
    global()?.eval_rooted(cmd)
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

    /// Evaluates GAP source text and returns the last result.
    ///
    /// `cmd` is parsed by GAP's ordinary command reader through an
    /// `InputTextString`. The returned [`GapElement`] is not rooted; root it
    /// before making further GAP calls if it must survive allocation.
    ///
    /// # Panics
    ///
    /// Panics if `cmd` contains an interior NUL byte, because GAP receives it as
    /// a C string.
    pub fn eval(&self, cmd: &str) -> Result<GapElement> {
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
                Ok(GapElement { obj })
            } else {
                Err(anyhow::anyhow!("Error evaluating command"))
            }
        }
    }

    /// Renders a GAP object with GAP's `PrintTo` and returns the resulting text.
    ///
    /// The wrapper reuses an internal GAP string as the output buffer, which is
    /// why this method takes `&mut self`.
    pub fn elem_string(&mut self, element: &GapElement) -> String {
        unsafe {
            SYSGAP_CallFunc2Args(self.print_fn, self.output_stream_handle, element.obj);
        }

        let cstr: &CStr = unsafe { CStr::from_ptr(GAP_CSTR_STRING(self.output_str_obj)) };
        let copy = cstr.to_string_lossy().to_string();

        unsafe {
            SET_LEN_STRING(self.output_str_obj, 0);
        }

        copy
    }

    /// Returns an element from a GAP list using a zero-based Rust index.
    ///
    /// GAP lists are one-based, so `idx` is incremented before calling into
    /// libgap. The returned element is not rooted.
    pub fn get_list_elem(&self, list: &GapElement, idx: usize) -> Result<GapElement> {
        unsafe {
            let obj = GAP_ElmList(list.obj, idx + 1);
            Ok(GapElement { obj })
        }
    }

    /// Roots a borrowed GAP object and returns an owned handle.
    ///
    /// The root is independent of `self`; `self` is present to keep the API
    /// tied to an initialized GAP runtime.
    pub fn root(&self, element: GapElement) -> GapObj {
        GapObj::new(element)
    }

    /// Evaluates GAP source text and roots the result.
    ///
    /// This is equivalent to `self.root(self.eval(cmd)?)`.
    pub fn eval_rooted(&self, cmd: &str) -> Result<GapObj> {
        Ok(self.root(self.eval(cmd)?))
    }

    /// Looks up a GAP global variable by name.
    ///
    /// The returned object is not rooted. Use [`Gap::global_rooted`] when the
    /// global value must be retained across later GAP allocations.
    pub fn global(&self, name: &str) -> Result<GapElement> {
        let raw_ptr = CString::new(name)
            .context("GAP global variable name contains an interior NUL byte")?
            .into_raw();
        let obj = unsafe { GAP_ValueGlobalVariable(raw_ptr) };
        unsafe {
            let _ = CString::from_raw(raw_ptr);
        }
        check_gap_error("looking up a global variable")?;
        Ok(GapElement { obj })
    }

    /// Calls a GAP function object with positional arguments.
    ///
    /// `function` must be a callable GAP object. The arguments are borrowed
    /// `Obj` handles and are passed to `GAP_CallFuncArray` without conversion.
    /// The returned object is not rooted.
    pub fn call_function(&self, function: &GapElement, args: &[&GapElement]) -> Result<GapElement> {
        let mut raw_args = args.iter().map(|arg| arg.obj).collect::<Vec<_>>();
        GAP_ERROR_OCCURRED.store(false, Ordering::SeqCst);
        let obj = unsafe {
            GAP_CallFuncArray(function.obj, raw_args.len() as UInt, raw_args.as_mut_ptr())
        };
        check_gap_error("calling a GAP function")?;
        Ok(GapElement { obj })
    }

    /// Looks up a GAP global function by name and calls it.
    ///
    /// This is a convenience wrapper around [`Gap::global`] and
    /// [`Gap::call_function`].
    pub fn call_global(&self, name: &str, args: &[&GapElement]) -> Result<GapElement> {
        let function = self.global(name)?;
        self.call_function(&function, args)
    }

    /// Looks up a GAP global variable and roots the result.
    pub fn global_rooted(&self, name: &str) -> Result<GapObj> {
        Ok(self.root(self.global(name)?))
    }

    /// Calls a GAP global function and roots the result.
    pub fn call_global_rooted(&self, name: &str, args: &[&GapElement]) -> Result<GapObj> {
        Ok(self.root(self.call_global(name, args)?))
    }

    /// Converts a Rust signed integer into GAP's immediate integer format.
    ///
    /// GAP small integers are encoded directly in the `Obj` word. The returned
    /// value does not need GC rooting because it is immediate.
    pub fn int(&self, value: isize) -> GapElement {
        GapElement {
            obj: unsafe { INTOBJ_INT(value as Int) },
        }
    }

    /// Converts a GAP integer object into a Rust `usize`.
    ///
    /// Returns an error if GAP produces a negative integer. The current
    /// implementation uses libgap's small-integer conversion and is intended for
    /// values known to fit in GAP's immediate integer representation.
    pub fn integer_usize(&self, element: &GapElement) -> Result<usize> {
        let value = unsafe { Int_ObjInt(element.obj) };
        if value < 0 {
            return Err(anyhow!(
                "GAP integer {value} cannot be represented as usize"
            ));
        }
        Ok(value as usize)
    }

    /// Converts GAP's `true` and `false` objects into a Rust `bool`.
    ///
    /// Returns an error for any non-boolean GAP object.
    pub fn boolean(&self, element: &GapElement) -> Result<bool> {
        unsafe {
            if element.obj == GAP_True {
                Ok(true)
            } else if element.obj == GAP_False {
                Ok(false)
            } else {
                Err(anyhow!("GAP object is not a boolean"))
            }
        }
    }

    /// Returns whether `element` is GAP's distinguished `fail` value.
    pub fn is_fail(&self, element: &GapElement) -> bool {
        unsafe { element.obj == GAP_Fail || element.obj == Fail }
    }

    /// Builds a mutable GAP plain list from already-created GAP objects.
    ///
    /// GAP lists are one-based, so each Rust slice element is written at
    /// position `idx + 1`. The list itself is a newly allocated GAP object and
    /// is not rooted unless the caller stores it in a [`GapObj`].
    pub fn list(&self, elements: &[GapElement]) -> GapElement {
        unsafe {
            let list = NEW_PLIST(TNUM_T_PLIST as UInt, elements.len() as Int);
            SET_LEN_PLIST(list, elements.len() as Int);
            for (idx, element) in elements.iter().enumerate() {
                SET_ELM_PLIST(list, idx as Int + 1, element.obj);
            }
            CHANGED_BAG(list);
            GapElement { obj: list }
        }
    }

    /// Builds a GAP plain list and roots it.
    pub fn list_rooted(&self, elements: &[GapElement]) -> GapObj {
        self.root(self.list(elements))
    }

    /// Returns the length of a GAP list.
    pub fn list_len(&self, list: &GapElement) -> usize {
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
    pub fn permutation_from_zero_based_images(&self, images: &[usize]) -> Result<GapElement> {
        let source = (1..=images.len())
            .map(|idx| self.int(idx as isize))
            .collect::<Vec<_>>();
        let target = images
            .iter()
            .map(|&image| self.int(image as isize + 1))
            .collect::<Vec<_>>();
        let source = self.list(&source);
        let target = self.list(&target);
        self.alloc(&source);
        self.alloc(&target);
        let result = self.call_global("MappingPermListList", &[&source, &target]);
        self.free(&target);
        self.free(&source);
        result
    }

    /// Builds a GAP permutation from zero-based images and roots it.
    pub fn permutation_from_zero_based_images_rooted(&self, images: &[usize]) -> Result<GapObj> {
        Ok(self.root(self.permutation_from_zero_based_images(images)?))
    }

    /// Computes zero-based images of a GAP permutation on `0..degree`.
    ///
    /// GAP's `OnPoints` action is evaluated on one-based points and each result
    /// is shifted back to Rust's zero-based convention.
    pub fn permutation_images_zero_based(
        &self,
        permutation: &GapElement,
        degree: usize,
    ) -> Result<Vec<usize>> {
        let on_points = self.global("OnPoints")?;
        (1..=degree)
            .map(|point| {
                let point = self.int(point as isize);
                let image = self.call_function(&on_points, &[&point, permutation])?;
                self.integer_usize(&image).and_then(|image| {
                    image
                        .checked_sub(1)
                        .ok_or_else(|| anyhow!("permutation sent a point outside [1..degree]"))
                })
            })
            .collect()
    }

    /// Removes one GC root for `obj`.
    ///
    /// This is the manual counterpart to [`Gap::alloc`]. Prefer [`GapObj`] for
    /// ordinary ownership because it releases roots automatically on drop.
    pub fn free(&self, obj: &GapElement) {
        unroot_obj(obj);
    }

    /// Adds a GC root for `obj`.
    ///
    /// Each call should be paired with [`Gap::free`] unless ownership is handed
    /// to a [`GapObj`]. Rooting is required for non-immediate GAP objects that
    /// outlive the GAP call that produced them.
    pub fn alloc(&self, obj: &GapElement) {
        root_obj(obj);
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
static mut OBJ_REFS: *mut Vec<GapElement> = ptr::null_mut();
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
fn root_obj(obj: &GapElement) {
    let _guard = OBJ_REFS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    unsafe {
        OBJ_REFS
            .as_mut()
            .expect("GAP object rooting is only available after GAP initialization")
            .push(obj.to_owned());
    }
}

/// Removes one matching root-table entry for `obj`.
///
/// Missing roots are ignored, matching the historic behavior of the wrapper's
/// manual `alloc`/`free` API.
fn unroot_obj(obj: &GapElement) {
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
    fn test_group() -> Result<()> {
        with_gap(|gap| {
            let group = gap.eval_rooted("Group((1,2,3),(1,2));")?;
            assert_eq!(
                gap.elem_string(group.as_element()),
                "Group( [ (1,2,3), (1,2) ] )"
            );
            Ok(())
        })
    }

    #[test]
    fn global_eval_roots_its_result() -> Result<()> {
        let group = gap_eval("Group((1,2,3),(1,2));")?;
        with_gap(|gap| {
            assert_eq!(
                gap.elem_string(group.as_element()),
                "Group( [ (1,2,3), (1,2) ] )"
            );
            Ok(())
        })
    }

    #[test]
    fn test_direct_product() -> Result<()> {
        with_gap(|gap| {
            let degree = gap.int(7);
            let s7 = gap.call_global_rooted("SymmetricGroup", &[&degree])?;
            let product =
                gap.call_global_rooted("DirectProduct", &[s7.as_element(), s7.as_element()])?;
            let order = gap.call_global("Order", &[product.as_element()])?;

            assert_eq!(gap.integer_usize(&order)?, 25_401_600);
            Ok(())
        })
    }

    #[test]
    fn test_nested_list() -> Result<()> {
        with_gap(|gap| {
            let outer_list = gap.eval_rooted("[[1, 2, 3], [4, 5, 6]];")?;
            assert_eq!(gap.list_len(outer_list.as_element()), 2);

            let inner_list = gap.root(gap.get_list_elem(outer_list.as_element(), 1)?);
            assert_eq!(gap.list_len(inner_list.as_element()), 3);

            let element = gap.get_list_elem(inner_list.as_element(), 1)?;
            assert_eq!(gap.integer_usize(&element)?, 5);
            assert_eq!(gap.elem_string(&element), "5");
            Ok(())
        })
    }

    #[test]
    fn test_echo() -> Result<()> {
        with_gap(|gap| {
            let hello = gap.eval_rooted("\"Hello, world!\";")?;
            assert_eq!(gap.elem_string(hello.as_element()), "Hello, world!");
            Ok(())
        })
    }

    #[test]
    fn test_smoke_one_plus_one() -> Result<()> {
        with_gap(|gap| {
            let gapdoc = gap.eval("LoadPackage(\"gapdoc\");")?;
            if !gap.boolean(&gapdoc).unwrap_or(false) {
                let roots = gap.eval("GAPInfo.RootPaths;")?;
                let root_paths = gap.elem_string(&roots);
                panic!("unable to load GAP package gapdoc; GAPInfo.RootPaths = {root_paths}");
            }

            let value = gap.eval("1+1;")?;
            assert_eq!(gap.integer_usize(&value)?, 2);
            Ok(())
        })
    }

    #[test]
    fn test_list_and_permutation_helpers() -> Result<()> {
        with_gap(|gap| {
            let elements = [gap.int(2), gap.int(4), gap.int(6)];
            let list = gap.list_rooted(&elements);
            assert_eq!(gap.list_len(list.as_element()), 3);

            let second = gap.get_list_elem(list.as_element(), 1)?;
            assert_eq!(gap.integer_usize(&second)?, 4);

            let permutation = gap.permutation_from_zero_based_images_rooted(&[2, 0, 1])?;
            assert_eq!(
                gap.permutation_images_zero_based(permutation.as_element(), 3)?,
                vec![2, 0, 1]
            );
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

    #[cfg(unix)]
    #[test]
    fn runtime_root_inference_does_not_probe_filesystem_root() {
        let roots = inferred_runtime_roots(Path::new("/tmp/gap-sys-fake-root"));

        assert!(!roots.contains(&PathBuf::from("/lib/gap")));
        assert!(!roots.contains(&PathBuf::from("/share/gap")));
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
