#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use anyhow::{anyhow, Context, Result};
use std::ffi::{c_char, c_int, CStr, CString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct Gap {
    print_fn: Obj,
    input_stream: Obj,
    output_str_obj: Obj,
    output_stream_handle: Obj,
}

impl Drop for Gap {
    fn drop(&mut self) {
        unsafe {
            SYSGAP_CloseOutput();
        }
    }
}

#[derive(Clone, Debug)]
pub struct GapElement {
    pub obj: Obj,
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

unsafe fn hex_str_to_ptr(hex_str: &str) -> Result<Bag, std::num::ParseIntError> {
    let without_prefix = hex_str.trim_start_matches("0x");
    let addr = usize::from_str_radix(without_prefix, 16)?;
    Ok(addr as Bag)
}

// Implement from string for GapElement
// Convert the hex string into a *mut Bag
impl From<&str> for GapElement {
    fn from(s: &str) -> Self {
        GapElement {
            obj: unsafe { hex_str_to_ptr(s.trim()).unwrap() },
        }
    }
}

impl Gap {
    pub fn init() -> Gap {
        Self::try_init().expect("Unable to initialize GAP")
    }

    pub fn try_init() -> Result<Gap> {
        let root = default_gap_root();
        Self::try_init_with_root(root)
    }

    pub fn init_with_root<P: AsRef<Path>>(root: P) -> Gap {
        Self::try_init_with_root(root).expect("Unable to initialize GAP")
    }

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

    pub fn get_list_elem(&self, list: &GapElement, idx: usize) -> Result<GapElement> {
        unsafe {
            let obj = GAP_ElmList(list.obj, idx + 1);
            Ok(GapElement { obj })
        }
    }

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

    pub fn call_function(&self, function: &GapElement, args: &[&GapElement]) -> Result<GapElement> {
        let mut raw_args = args.iter().map(|arg| arg.obj).collect::<Vec<_>>();
        GAP_ERROR_OCCURRED.store(false, Ordering::SeqCst);
        let obj = unsafe {
            GAP_CallFuncArray(function.obj, raw_args.len() as UInt, raw_args.as_mut_ptr())
        };
        check_gap_error("calling a GAP function")?;
        Ok(GapElement { obj })
    }

    pub fn call_global(&self, name: &str, args: &[&GapElement]) -> Result<GapElement> {
        let function = self.global(name)?;
        self.call_function(&function, args)
    }

    pub fn int(&self, value: isize) -> GapElement {
        GapElement {
            obj: unsafe { INTOBJ_INT(value as Int) },
        }
    }

    pub fn integer_usize(&self, element: &GapElement) -> Result<usize> {
        let value = unsafe { Int_ObjInt(element.obj) };
        if value < 0 {
            return Err(anyhow!(
                "GAP integer {value} cannot be represented as usize"
            ));
        }
        Ok(value as usize)
    }

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

    pub fn is_fail(&self, element: &GapElement) -> bool {
        unsafe { element.obj == GAP_Fail || element.obj == Fail }
    }

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

    pub fn list_len(&self, list: &GapElement) -> usize {
        unsafe { LEN_LIST(list.obj) as usize }
    }

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

    pub fn free(&self, obj: &GapElement) {
        unsafe {
            let refs = OBJ_REFS.as_mut().unwrap();
            if let Some(idx) = refs.iter().position(|x| x.obj == obj.obj) {
                refs.remove(idx);
            }
        }
    }

    pub fn alloc(&self, obj: &GapElement) {
        unsafe {
            OBJ_REFS.as_mut().unwrap().push(obj.to_owned());
        }
    }
}

fn check_gap_error(context: &str) -> Result<()> {
    if GAP_ERROR_OCCURRED.swap(false, Ordering::SeqCst) {
        Err(anyhow!("GAP reported an error while {context}"))
    } else {
        Ok(())
    }
}

fn default_gap_root() -> PathBuf {
    std::env::var_os("GAP_SYS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("GAP_SYS_GAP_ROOT")))
}

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

fn is_gap_runtime_root(root: &Path) -> bool {
    root.join("lib").join("init.g").is_file() || root.join("pkg").is_dir()
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

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

// Garbage collector interface

static mut OBJ_REFS: *mut Vec<GapElement> = ptr::null_mut();
static GAP_ERROR_OCCURRED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn gap_error_callback() {
    GAP_ERROR_OCCURRED.store(true, Ordering::SeqCst);
}

unsafe extern "C" fn mark_bag() {
    for o in &*OBJ_REFS {
        SYSGAP_MarkBag(o.obj);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Due to a bug which I don't feel like fixing right now, tests can't run in parallel.
    // Also, CI won't have GAP installed, so we skip the tests.

    #[ignore]
    #[test]
    fn test_group() {
        let mut gap = Gap::init();
        let gap_element = gap.eval("Group((1,2,3),(1,2));").unwrap();
        assert_eq!(gap.elem_string(&gap_element), "Group( [ (1,2,3), (1,2) ] )");
    }

    #[ignore]
    #[test]
    fn test_direct_product() {
        let mut gap = Gap::init();
        gap.eval("a:=DirectProduct(SymmetricGroup(7), SymmetricGroup(7));")
            .unwrap();
        let obj = gap.eval("Order(a);").unwrap();
        let order: usize = gap.elem_string(&obj).parse().unwrap();
        assert_eq!(order, 25401600);
    }

    #[ignore]
    #[test]
    fn test_nested_list() {
        let mut gap = Gap::init();
        let outer_list = gap.eval("[[1, 2, 3], [4, 5, 6]];;").unwrap();
        let inner_list = gap.get_list_elem(&outer_list, 1).unwrap();
        let element = gap.get_list_elem(&inner_list, 1).unwrap();
        let string = gap.elem_string(&element);
        assert_eq!(string, "5");
    }

    #[ignore]
    #[test]
    fn test_echo() {
        let mut gap = Gap::init();
        let hello = gap.eval("\"Hello, world!\";").unwrap();
        let string = gap.elem_string(&hello);
        assert_eq!(string, "Hello, world!");
    }

    #[ignore]
    #[test]
    fn test_smoke_one_plus_one() {
        let mut gap = Gap::init();
        let gapdoc = gap.eval("LoadPackage(\"gapdoc\");").unwrap();
        let gapdoc_loaded = gap.elem_string(&gapdoc);
        if gapdoc_loaded != "true" {
            let roots = gap.eval("GAPInfo.RootPaths;").unwrap();
            let root_paths = gap.elem_string(&roots);
            panic!("unable to load GAP package gapdoc; GAPInfo.RootPaths = {root_paths}");
        }
        let value = gap.eval("1+1;").unwrap();
        assert_eq!(gap.elem_string(&value), "2");
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
