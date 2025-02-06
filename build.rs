use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to look for shared libraries in the specified directory
    println!("cargo:rustc-link-search={}", env::var("BASE_FOLDER").unwrap().as_str());

    // Tell cargo where to look for the shared object when running the program
    println!("cargo:rustc-env=$LD_LIBRARY_PATH:LD_LIBRARY_PATH={}", env::var("BASE_FOLDER").unwrap().as_str());

    // Tell cargo to tell rustc to link the shuriken lib
    println!("cargo:rustc-link-lib=shuriken");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .headers([
            format!("{}include/shuriken/api/C/shuriken_core_data.h",
                    env::var("BASE_FOLDER").unwrap().as_str()).as_str(),
            format!("{}include/shuriken/api/C/shuriken_core.h",
                    env::var("BASE_FOLDER").unwrap().as_str()).as_str(),
        ])
        .clang_arg("-std=c++17")
        .clang_arg("-x")
        .clang_arg("c++")
        .clang_arg(format!("-I{}/include/", env::var("BASE_FOLDER").unwrap().as_str()))
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
