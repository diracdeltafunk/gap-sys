extern crate bindgen;

mod gap_config;

use gap_config::{
    discover_gap_config, wrapper_header, DiscoveryEnv, GAP_SYS_GAP_BIN, GAP_SYS_INCLUDE_DIRS,
    GAP_SYS_LIB_DIRS, GAP_SYS_ROOT,
};
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=gap_config.rs");
    println!("cargo:rerun-if-env-changed={GAP_SYS_ROOT}");
    println!("cargo:rerun-if-env-changed={GAP_SYS_GAP_BIN}");
    println!("cargo:rerun-if-env-changed={GAP_SYS_INCLUDE_DIRS}");
    println!("cargo:rerun-if-env-changed={GAP_SYS_LIB_DIRS}");

    let gap_config = discover_gap_config(&DiscoveryEnv::from_process_env())
        .unwrap_or_else(|err| panic!("Unable to discover GAP installation: {err}"));

    for lib_dir in &gap_config.lib_dirs {
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    }
    println!("cargo:rustc-link-lib=gap");
    println!(
        "cargo:rustc-env=GAP_SYS_GAP_ROOT={}",
        gap_config.root.display()
    );

    let output_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let wrapper_path = output_path.join("wrapper.h");
    fs::write(&wrapper_path, wrapper_header(&gap_config.header_layout))
        .expect("Unable to write generated wrapper.h");

    let mut builder = bindgen::Builder::default()
        .header(wrapper_path.to_string_lossy())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate_comments(false)
        .wrap_static_fns(true);

    for include_dir in &gap_config.include_dirs {
        builder = builder.clang_arg(format!("-I{}", include_dir.display()));
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let mut cc_build = cc::Build::new();
    for include_dir in &gap_config.include_dirs {
        cc_build.include(include_dir);
    }

    cc_build
        .file(std::env::temp_dir().join("bindgen").join("extern.c"))
        .warnings(false)
        .opt_level(3)
        .out_dir(&output_path)
        .compile("extern");

    println!("cargo:rustc-link-search=native={}", output_path.display());
    println!("cargo:rustc-link-lib=static=extern");

    bindings
        .write_to_file(output_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
