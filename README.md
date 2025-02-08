# shuriken-bindings

Safe Rust bindings for the [Shuriken bytecode analyzer](https://github.com/Shuriken-Group/Shuriken-Analyzer).

## Usage

Add this crate to your `Cargo.toml` file:

```
cargo add shuriken-bindings
```

You must have downloaded and built the Shuriken analyzer library to use this
crate. Please refer to their [installation
instructions](https://github.com/Shuriken-Group/Shuriken-Analyzer?tab=readme-ov-file#installation)
for the relevant details.

When building your crate with the bindings you must set the `BASE_FOLDER`
environment variable to point to the build folder of Shuriken. You can use the
`config.toml` file for Cargo to set this up. In you crate root folder, add the
following to `.cargo/config.toml` ([requires Cargo version 1.56 and up](https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#configurable-env)):

```
[env]
BASE_FOLDER = "/path/to/your/build/folder"
```

## Current status

We only provide bindings for the C API for the Shuriken analyzer. As of this
writing, some features are not yet available through the C API. When features
are added we will update to bindings to support them.
