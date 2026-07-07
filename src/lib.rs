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

pub struct Gap {
    print_fn: Obj,
    input_stream: Obj,
    output_stream: TypOutputFile,
    output_str_obj: Obj,
    output_stream_handle: Obj,
}

impl Drop for Gap {
    fn drop(&mut self) {
        unsafe {
            CloseOutput(&mut self.output_stream);
        }
    }
}

#[derive(Clone)]
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

        let root_arg = root.to_string_lossy().into_owned();
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

            GAP_Initialize(
                c_args.len() as c_int - 1,
                c_args.as_mut_ptr(),
                Some(mark_bag),
                None,
                1,
            );
        }

        let output_text_str_operation = unsafe {
            let raw_ptr = CString::new("OutputTextString").unwrap().into_raw();
            let obj = ValGVar(GVarName(raw_ptr));
            let _ = CString::from_raw(raw_ptr);
            obj
        };

        let (output_stream, output_str_obj, output_stream_handle) = unsafe {
            let output_str_obj = NEW_STRING(0);
            let handle_obj = DoOperation2Args(output_text_str_operation, output_str_obj, GAP_True);
            let mut output: TypOutputFile = std::mem::zeroed();
            if OpenOutputStream(&mut output, handle_obj) != 1 {
                return Err(anyhow!("Unable to open GAP output stream"));
            }
            (output, output_str_obj, handle_obj)
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
            output_stream,
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
            GAP_CallFunc2Args(self.print_fn, self.output_stream_handle, element.obj);
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

    pub fn free(&self, obj: &GapElement) {
        unsafe {
            OBJ_REFS.as_mut().unwrap().retain(|x| x.obj != obj.obj);
        }
    }

    pub fn alloc(&self, obj: &GapElement) {
        unsafe {
            OBJ_REFS.as_mut().unwrap().push(obj.to_owned());
        }
    }
}

fn default_gap_root() -> PathBuf {
    std::env::var_os("GAP_SYS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("GAP_SYS_GAP_ROOT")))
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

unsafe extern "C" fn mark_bag() {
    for o in &*OBJ_REFS {
        GAP_MarkBag(o.obj);
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
        let value = gap.eval("1+1;").unwrap();
        assert_eq!(gap.elem_string(&value), "2");
    }
}
