use std::env;
use std::path::PathBuf;

const BASE_FOLDER: &str = "/home/jgamba/dev/build/Shuriken-Analyzer/build/shuriken/";

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search={}", BASE_FOLDER);

    // Tell cargo where to look for the shared object when running the program
    println!("cargo:rustc-env=LD_LIBRARY_PATH={}", BASE_FOLDER);

    // Tell cargo to tell rustc to link the shuriken lib
    println!("cargo:rustc-link-lib=shuriken");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .headers([
            "/home/jgamba/dev/shuriken/Shuriken-Analyzer/shuriken/include/shuriken/api/C/shuriken_core.h",
            "/home/jgamba/dev/shuriken/Shuriken-Analyzer/shuriken/include/shuriken/api/C/shuriken_core_data.h"
        ])
        .clang_arg("-std=c++17")
        .clang_arg("-x")
        .clang_arg("c++")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/shuriken_core.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("shuriken_core.rs"))
        .expect("Couldn't write bindings!");
}
