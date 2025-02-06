#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#![allow(dead_code)]
#![allow(unused_variables)]

pub mod parser;
pub mod disassembler;
pub mod analysis;
pub mod dvm_access_flags;

use std::path::Path;
use std::ffi::{ CStr, CString };
use std::collections::HashMap;

use crate::parser::{
    DvmMethod,
    DvmClass
};
use crate::disassembler::DvmDisassembledMethod;
use crate::analysis::{
    DvmStringAnalysis,
    DvmFieldAnalysis,
    DvmMethodAnalysis,
    DvmClassAnalysis
};


mod shuriken {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/shuriken_core.rs"));
}

/// Type alias for Shuriken's `hDexContext`
///
/// This struct also contains caches of raw pointers and of the
/// different analysis classes.
#[derive(Debug)]
pub struct DexContext {
    ptr: shuriken::hDexContext,

    class_ptrs: HashMap<String, *mut shuriken::hdvmclass_t>,
    method_ptrs: HashMap<String, *mut shuriken::hdvmmethod_t>,

    class_analyses: HashMap<String, DvmClassAnalysis>,
    method_analyses: HashMap<String, DvmMethodAnalysis>,
    field_analyses: HashMap<String, DvmFieldAnalysis>,
}

/// Type alias for Shuriken's `hApkContext`
#[derive(Debug)]
pub struct ApkContext(shuriken::hApkContext);

// --------------------------- Parser API ---------------------------

impl Drop for DexContext {
    fn drop(&mut self) {
        unsafe {
            shuriken::destroy_dex(self.ptr);
        }
    }
}

impl DexContext {
    /// Main method from the DEX core API
    ///
    /// Parse a DEX file and return a DEX context.
    /// TODO: make sure we correctly handle non-ascii paths
    pub fn parse_dex(filepath: &Path) -> Self {
        let c_str = CString::new(filepath.to_path_buf().into_os_string().into_string().unwrap()).unwrap();
        let c_world = c_str.as_ptr();

        let ptr = unsafe { shuriken::parse_dex(c_world) };

        Self {
            ptr,
            class_ptrs: HashMap::new(),
            method_ptrs: HashMap::new(),
            class_analyses: HashMap::new(),
            method_analyses: HashMap::new(),
            field_analyses: HashMap::new(),
        }
    }

    /// Get the number of strings in the DEX file
    pub fn get_number_of_strings(&self) -> usize {
        unsafe {
            shuriken::get_number_of_strings(self.ptr)
        }
    }

    /// Get a string given its ID
    pub fn get_string_by_id(&self, string_id: usize) -> Option<String> {
        unsafe {
            let c_string = shuriken::get_string_by_id(self.ptr, string_id);
            if let Ok(string) = CStr::from_ptr(c_string).to_str() {
                Some(string.to_owned())
            } else {
                None
            }
        }
    }

    /// Get the number of classes in the DEX file
    pub fn get_number_of_classes(&self) -> usize {
        unsafe {
            shuriken::get_number_of_classes(self.ptr).into()
        }
    }

    /// Get a class structure given an ID
    pub fn get_class_by_id(&mut self, id: u16) -> Option<DvmClass> {
        let dvm_class_ptr = unsafe { shuriken::get_class_by_id(self.ptr, id) };

        if ! dvm_class_ptr.is_null() {
            let dvm_class = DvmClass::from_ptr(unsafe { *dvm_class_ptr });
            self.class_ptrs.insert(String::from(dvm_class.class_name()), dvm_class_ptr);
            Some(dvm_class)
        } else {
            None
        }
    }

    /// Get a class structure given a class name
    pub fn get_class_by_name(&mut self, class_name: &str) -> Option<DvmClass> {
        let c_str = CString::new(class_name)
            .expect("CString::new failed");

        let class_ptr = unsafe { shuriken::get_class_by_name(self.ptr, c_str.as_ptr()) };
        if ! class_ptr.is_null() {
            let dvm_class = DvmClass::from_ptr(unsafe { *class_ptr });
            self.class_ptrs.insert(String::from(dvm_class.class_name()), class_ptr);
            Some(dvm_class)
        } else {
            None
        }
    }

    /// Get a method structure given a full dalvik name.
    pub fn get_method_by_name(&mut self, method_name: &str) -> Option<DvmMethod> {
        let c_str = CString::new(method_name)
            .expect("CString::new failed");

        let method_ptr = unsafe { shuriken::get_method_by_name(self.ptr, c_str.as_ptr()) };
        if ! method_ptr.is_null() {
            let dvm_method = unsafe { DvmMethod::from_ptr(*method_ptr) };
            self.method_ptrs.insert(String::from(dvm_method.demangled_name()), method_ptr);
            Some(dvm_method)
        } else {
            None
        }
    }

    // --------------------------- Disassembler API ---------------------------

    /// Disassemble a DEX file and generate an internal DexDisassembler
    pub fn disassemble_dex(&self) {
        unsafe {
            shuriken::disassemble_dex(self.ptr)
        }
    }

    /// Get a method structure given a full dalvik name.
    pub fn get_disassembled_method(&mut self, method_name: &str) -> Option<DvmDisassembledMethod> {
        let c_str = CString::new(method_name)
            .expect("CString::new failed");

        let dvm_method = self.get_method_by_name(method_name)
                             .expect("Cannot find function");
        let dvm_disas = unsafe { shuriken::get_disassembled_method(self.ptr, c_str.as_ptr()) };

        if ! dvm_disas.is_null() {
            Some(unsafe { DvmDisassembledMethod::from_dvmdisassembled_method_t(*dvm_disas, dvm_method) })
        } else {
            eprintln!("No disassembled method. Did you run `DexContext::disassemble_dex()`?");
            None
        }
    }

    // --------------------------- Analysis API ---------------------------

    /// Create a DEX analysis object inside of &self
    ///
    /// Optionally this function can create the cross-refs. In that case the analysis will take longer.
    /// To obtain the analysis, you must also call [`analyze_classes`](fn.analyze_classes.html)
    pub fn create_dex_analysis(&self, create_xrefs: bool) {
        let xrefs = if create_xrefs {
            1
        } else {
            0
        };

        unsafe {
            shuriken::create_dex_analysis(self.ptr, xrefs)
        }
    }

    /// Analyze the classes, add fields and methods into the classes, optionally create the xrefs
    pub fn analyze_classes(&self) {
        unsafe {
            shuriken::analyze_classes(self.ptr)
        }
    }

    /// Obtain a `DvmClassAnalysis` given a `DvmClass`
    pub fn get_analyzed_class_by_hdvmclass(&self, class: &DvmClass) -> Option<DvmClassAnalysis> {
        let class_ptr = match self.class_ptrs.get(class.class_name()) {
            Some(ptr) => ptr,
            None => return None
        };


        let analysis = unsafe {
            DvmClassAnalysis::from_ptr(*shuriken::get_analyzed_class_by_hdvmclass(self.ptr, *class_ptr))
        };

        Some(analysis)
    }

    /// Obtain a `DvmClassAnalysis` given a class name
    pub fn get_analyzed_class(&self, class_name: &str) -> Option<DvmClassAnalysis> {
        let c_str = CString::new(class_name)
            .expect("CString::new failed");

        let class_analysis_ptr = unsafe {
            shuriken::get_analyzed_class(self.ptr, c_str.as_ptr())
        };

        match class_analysis_ptr.is_null() {
            true => None,
            false => {
                let dvm_class_analysis = unsafe { DvmClassAnalysis::from_ptr(*class_analysis_ptr) };
                Some(dvm_class_analysis)
            }
        }
    }

    /// Obtain one DvmMethodAnalysis given its DvmMethod
    pub fn get_analyzed_method_by_hdvmmethod(&self, method: &DvmMethod ) -> &DvmMethodAnalysis {
        todo!();
    }

    /// Obtain one DvmMethodAnalysis given its name
    pub fn get_analyzed_method(&self, method_full_name: &str) -> &DvmMethodAnalysis {
        todo!();
    }
}

// C - APK part of the CORE API from ShurikenLib
// --------------------------- Parser API ---------------------------

impl ApkContext {
    /// main method from the APK Core API it parses the APK file and it retrieves a context object
    pub fn parse_apk(filepath: String, create_xref: bool) -> Self {
        todo!();
    }

    /// Since the context object use dynamic memory this method will properly destroy the object
    ///
    /// TODO: implement using `Drop` instead
    pub fn destroy_apk(context: ApkContext) {
        todo!();
    }

    /// Get the number of DEX files in an APK
    ///
    /// APKs may contain multiple DEX files. This function retrieve the number of DEX files in an APK.
    pub fn get_number_of_dex_files(&self) -> usize {
        todo!();
    }

    /// Given an index, retrieve the name of one of the DEX file
    pub fn get_dex_file_by_index(&self, idx: usize) -> String {
        todo!();
    }

    /// Get the number of classes in an APK
    ///
    /// Every DEX file contains a number of classes. This function retrieves the total number of
    /// classes in an APK
    pub fn get_number_of_classes_for_dex_file(&self, dex_file: &str) -> usize {
        todo!();
    }

    /// Retrieve one of the `DvmClass` from a DEX file
    pub fn get_hdvmclass_from_dex_by_index(&self, dex_file: &str, idx: usize) -> &DvmClass {
        todo!();
    }

    /// Retrieve the number of strings from a given DEX
    pub fn get_number_of_strings_from_dex(&self, dex_file: &str) -> usize {
        todo!();
    }

    /// Get a string from a DEX by its index
    pub fn get_string_by_id_from_dex(&self, dex_file: &str, idx: usize) -> &str {
        todo!();
    }

    // --------------------------- Disassembly API ---------------------------

    /// Get a method structure given a full dalvik name.
    pub fn get_disassembled_method_from_apk(&self, method_name: &str) -> &DvmDisassembledMethod {
        todo!();
    }

    // --------------------------- Analysis API ---------------------------

    /// Obtain one `DvmClassAnalysis` given its `DvmClass`
    pub fn get_analyzed_class_by_hdvmclass_from_apk(&self, class: DvmClass) -> DvmClassAnalysis {
        todo!();
    }

    /// Obtain one `DvmClassAnalysis` given its name
    pub fn get_analyzed_class_from_apk(&self, class_name: &str) -> DvmClassAnalysis {
        todo!();
    }

    /// Obtain one `DvmMethodAnalysis` given its `DvmMethodAnalysis`
    pub fn get_analyzed_method_by_hdvmmethod_from_apk(&self, method: DvmMethod) -> DvmMethodAnalysis {
        todo!();
    }

    /// Obtain one `DvmMethodAnalysis` given its name
    pub fn get_analyzed_method_from_apk(&self, method_full_name: &str) -> DvmMethodAnalysis {
        todo!();
    }

    /// Obtain the number of `DvmMethodAnalysis` objects in the APK
    pub fn get_number_of_method_analysis_objects(&self) -> usize {
        todo!();
    }

    /// Obtain a `DvmMethodAnalysis` object from the APK by idx
    pub fn get_analyzed_method_by_idx(&self, idx: usize) -> DvmMethodAnalysis {
        todo!();
    }

    /// Obtain a `DvmStringAnalysis` given a string
    pub fn get_analyzed_string_from_apk(&self, string: &str) -> DvmStringAnalysis {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    mod dex {
        use super::super::*;

        use std::fs;
        use std::path::PathBuf;

        use parser::*;
        use dvm_access_flags::{ DvmAccessFlag, DvmAccessFlagType };

        const TEST_FILES_PATH: &str = "test_files/";

        #[test]
        fn test_parse_dex() {
            let paths = fs::read_dir(TEST_FILES_PATH).unwrap();

            for path in paths {
                let path = path.unwrap().path();

                // Only testing DEX files
                if path.extension().unwrap() == "apk" {
                    continue;
                }

                let context = DexContext::parse_dex(&path);
            }
        }

        #[test]
        fn test_nb_strings() {
            use std::collections::HashMap;

            let counts = HashMap::from([
                ("test_files/_pi.dex", 32usize),
                ("test_files/_null.dex", 23),
                ("test_files/_float.dex", 71),
                ("test_files/_test_lifter.dex", 16),
                ("test_files/_long.dex", 28),
                ("test_files/_double.dex", 71),
                ("test_files/DexParserTest.dex", 33),
                ("test_files/_exception.dex", 31),
                ("test_files/_cast.dex", 29),
                ("test_files/test_zip.apk", 0),
                ("test_files/_loop.dex", 23),
                ("test_files/TestFieldsLifter.dex", 44),
                ("test_files/_instance.dex", 28),
                ("test_files/_switch.dex", 33),
                ("test_files/_int.dex", 27)
            ]);

            let paths = fs::read_dir(TEST_FILES_PATH).unwrap();

            for path in paths {
                let path = path.unwrap().path();

                // Only testing DEX files
                if path.extension().unwrap() == "apk" {
                    continue;
                }

                let context = DexContext::parse_dex(&path);
                let count = context.get_number_of_strings();

                assert_eq!(count, *counts.get(&path.to_str().unwrap()).unwrap());
            }
        }

        #[test]
        fn test_get_string() {
            let strings = vec![
                " and ",
                " is: ",
                "<init>",
                "DexParserTest.java",
                "Field 1: ",
                "Field 2: ",
                "Hello, Dex Parser!",
                "I",
                "III",
                "L",
                "LDexParserTest;",
                "LI",
                "LL",
                "Ljava/io/PrintStream;",
                "Ljava/lang/Object;",
                "Ljava/lang/String;",
                "Ljava/lang/StringBuilder;",
                "Ljava/lang/System;",
                "Sum of ",
                "This is a test message printed from DexParserTest class.",
                "V",
                "VL",
                "[Ljava/lang/String;",
                "append",
                "calculateSum",
                "field1",
                "field2",
                "main",
                "out",
                "printMessage",
                "println",
                "toString",
                "~~D8{\"backend\":\"dex\",\"compilation-mode\":\"debug\",\"has-checksums\":false,\"min-api\":1,\"version\":\"3.3.20-dev+aosp5\"}"
            ];

            let context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));

            assert_eq!(context.get_number_of_strings(), 33);

            for idx in 0..context.get_number_of_strings() {
                let string = context.get_string_by_id(idx);
                assert!(string.is_some());
                assert_eq!(string.unwrap(), strings[idx]);
            }
        }

        #[test]
        fn test_fields() {
            use std::collections::HashMap;

            let fields = [HashMap::from([
                    ("name", "field1"),
                    ("flags", "2"),
                    ("type", "I")
                ]),
                HashMap::from([
                    ("name", "field2"),
                    ("flags", "2"),
                    ("type", "Ljava/lang/String;"),
                ])];

            let mut context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));
            let class = context.get_class_by_id(0);

            assert!(class.is_some());
            let class = class.unwrap();

            assert_eq!(class.class_name(), "DexParserTest");
            assert_eq!(class.super_class(), "java.lang.Object");
            assert_eq!(class.source_file(), "DexParserTest.java");

            assert_eq!(class.access_flags(), vec![DvmAccessFlag::ACC_PUBLIC]);
            assert_eq!(class.instance_fields_size(), 2);
            assert_eq!(class.static_fields_size(), 0);

            let class_descriptor = String::from("LDexParserTest;");
            let access_flags = [DvmAccessFlag::ACC_PUBLIC];

            for (idx, field) in class.instance_fields().iter().enumerate() {
                let access_flags = DvmAccessFlag::parse(
                    fields[idx]["flags"].parse::<u32>().unwrap(),
                    DvmAccessFlagType::Field
                );

                assert_eq!(field.class_name(), class_descriptor);
                assert_eq!(field.name(), fields[idx]["name"]);
                assert_eq!(field.access_flags(), access_flags);

                if fields[idx]["type"].starts_with("L") {
                    assert_eq!(field.field_type(), DexTypes::Class);
                    assert_eq!(field.fundamental_value(), DexBasicTypes::FundamentalNone);
                    assert_eq!(field.type_value(), "Ljava/lang/String;");
                } else {
                    assert_eq!(field.field_type(), DexTypes::Fundamental);
                    assert_eq!(field.fundamental_value(), DexBasicTypes::Int);
                    assert_eq!(field.type_value(), "I");
                }
            }
        }

        #[test]
        fn test_methods() {
            use std::collections::HashMap;

            let methods = [HashMap::from([
                    ("dalvik_name", "LDexParserTest;-><init>()V"),
                    ("flags", "1"),
                ]),
                HashMap::from([
                    ("dalvik_name", "LDexParserTest;->calculateSum(II)I"),
                    ("flags", "2"),
                ]),
                HashMap::from([
                    ("dalvik_name", "LDexParserTest;->main([Ljava/lang/String;)V"),
                    ("flags", "9"),
                ]),
                HashMap::from([
                    ("dalvik_name", "LDexParserTest;->printMessage()V"),
                    ("flags", "2"),
                ])];

            let mut context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));
            let class = context.get_class_by_id(0);

            assert!(class.is_some());
            let class = class.unwrap();

            assert_eq!(class.class_name(), "DexParserTest");
            assert_eq!(class.super_class(), "java.lang.Object");
            assert_eq!(class.source_file(), "DexParserTest.java");

            assert_eq!(class.access_flags(), vec![DvmAccessFlag::ACC_PUBLIC]);
            assert_eq!(class.direct_methods_size(), 4);
            assert_eq!(class.virtual_methods_size(), 0);

            let class_descriptor = String::from("LDexParserTest;");
            let access_flags = [DvmAccessFlag::ACC_PUBLIC];

            for (idx, method) in class.direct_methods().iter().enumerate() {
                let access_flags = DvmAccessFlag::parse(
                    methods[idx]["flags"].parse::<u32>().unwrap(),
                    DvmAccessFlagType::Method
                );

                assert_eq!(method.class_name(), class_descriptor);
                assert_eq!(method.dalvik_name(), methods[idx]["dalvik_name"]);
                assert_eq!(method.access_flags(), access_flags);
            }
        }

        #[test]
        fn test_get_class_by_name() {
            let mut context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));
            let class = context.get_class_by_name("DexParserTest");

            assert!(class.is_some());
            assert_eq!(class.as_ref().unwrap().class_name(), "DexParserTest");
            assert_eq!(class.as_ref().unwrap().super_class(), "java.lang.Object");
            assert_eq!(class.as_ref().unwrap().source_file(), "DexParserTest.java");
            assert_eq!(class.as_ref().unwrap().access_flags(), vec![DvmAccessFlag::ACC_PUBLIC]);
        }

        #[test]
        fn test_get_method_by_name() {
            let mut context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));
            let method = context.get_method_by_name("LDexParserTest;->printMessage()V");

            assert!(method.is_some());
            assert_eq!(method.as_ref().unwrap().method_name(), "printMessage");
            assert_eq!(method.as_ref().unwrap().class_name(), "LDexParserTest;");
            assert_eq!(method.as_ref().unwrap().prototype(), "()V");
            assert_eq!(method.as_ref().unwrap().access_flags(), vec![DvmAccessFlag::ACC_PRIVATE]);
        }

        #[test]
        fn test_disassemble_dex() {
            let paths = fs::read_dir(TEST_FILES_PATH).unwrap();

            for path in paths {
                let path = path.unwrap().path();

                // Only testing DEX files
                if path.extension().unwrap() == "apk" {
                    continue;
                }

                let context = DexContext::parse_dex(&path);
                context.disassemble_dex();
            }
        }

        #[test]
        fn test_get_disassembled_method() {
            use std::collections::HashMap;

            let methods = HashMap::from([
                (
                    String::from("LDexParserTest;-><init>()V"),
                    vec![
                        ".method constructor public LDexParserTest;-><init>()V",
                        ".registers 2",
                        "00000000 invoke-direct {v1}, Ljava/lang/Object;-><init>()V // method@5",
                        "00000006 const/16 v0, 42",
                        "0000000a iput v0, v1, DexParserTest->field1 int // field@0",
                        "0000000e const-string v0, \"Hello, Dex Parser!\" // string@6",
                        "00000012 iput-object v0, v1, DexParserTest->field2 java.lang.String // field@1",
                        "00000016 return-void",
                        ".end method"
                    ]
                ),
                (
                    String::from("LDexParserTest;->calculateSum(II)I"),
                    vec![
                        ".method private LDexParserTest;->calculateSum(II)I",
                        ".registers 7",
                        "00000000 add-int v0, v5, v6",
                        "00000004 sget-object v1, java.lang.System->out java.io.PrintStream // field@2",
                        "00000008 new-instance v2, Ljava/lang/StringBuilder; // type@5",
                        "0000000c invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V // method@6",
                        "00000012 const-string v3, \"Sum of \" // string@18",
                        "00000016 invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "0000001c move-result-object v2",
                        "0000001e invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7",
                        "00000024 move-result-object v5",
                        "00000026 const-string v2, \" and \" // string@0",
                        "0000002a invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "00000030 move-result-object v5",
                        "00000032 invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7",
                        "00000038 move-result-object v5",
                        "0000003a const-string v6, \" is: \" // string@1",
                        "0000003e invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "00000044 move-result-object v5",
                        "00000046 invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7",
                        "0000004c move-result-object v5",
                        "0000004e invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String; // method@9",
                        "00000054 move-result-object v5",
                        "00000056 invoke-virtual {v1, v5}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4",
                        "0000005c return v0",
                        ".end method"
                    ]
                ),
                (
                    String::from("LDexParserTest;->main([Ljava/lang/String;)V"),
                    vec![
                        ".method public static LDexParserTest;->main([Ljava/lang/String;)V",
                        ".registers 3",
                        "00000000 new-instance v2, LDexParserTest; // type@1",
                        "00000004 invoke-direct {v2}, LDexParserTest;-><init>()V // method@0",
                        "0000000a invoke-direct {v2}, LDexParserTest;->printMessage()V // method@3",
                        "00000010 const/16 v0, 10",
                        "00000014 const/16 v1, 20",
                        "00000018 invoke-direct {v2, v0, v1}, LDexParserTest;->calculateSum(II)I // method@1",
                        "0000001e return-void",
                        ".end method"
                    ]
                ),
                (
                    String::from("LDexParserTest;->printMessage()V"),
                    vec![
                        ".method private LDexParserTest;->printMessage()V",
                        ".registers 4",
                        "00000000 sget-object v0, java.lang.System->out java.io.PrintStream // field@2",
                        "00000004 new-instance v1, Ljava/lang/StringBuilder; // type@5",
                        "00000008 invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V // method@6",
                        "0000000e const-string v2, \"Field 1: \" // string@4",
                        "00000012 invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "00000018 move-result-object v1",
                        "0000001a iget v2, v3, DexParserTest->field1 int // field@0",
                        "0000001e invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7",
                        "00000024 move-result-object v1",
                        "00000026 invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String; // method@9",
                        "0000002c move-result-object v1",
                        "0000002e invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4",
                        "00000034 sget-object v0, java.lang.System->out java.io.PrintStream // field@2",
                        "00000038 new-instance v1, Ljava/lang/StringBuilder; // type@5",
                        "0000003c invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V // method@6",
                        "00000042 const-string v2, \"Field 2: \" // string@5",
                        "00000046 invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "0000004c move-result-object v1",
                        "0000004e iget-object v2, v3, DexParserTest->field2 java.lang.String // field@1",
                        "00000052 invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "00000058 move-result-object v1",
                        "0000005a invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String; // method@9",
                        "00000060 move-result-object v1",
                        "00000062 invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4",
                        "00000068 sget-object v0, java.lang.System->out java.io.PrintStream // field@2",
                        "0000006c const-string v1, \"This is a test message printed from DexParserTest class.\" // string@19",
                        "00000070 invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4",
                        "00000076 return-void",
                        ".end method"
                    ]
                )
            ]);

            let mut context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));

            // Check that we get nothing if we have not run `DexContext::disassemble_dex()`
            let dvm_method = context.get_disassembled_method(
                "LDexParserTest;->printMessage()V"
            );
            assert!(dvm_method.is_none());

            context.disassemble_dex();

            for (method, code) in methods.iter() {
                let dvm_method = context.get_disassembled_method(method);
                assert!(dvm_method.is_some());

                let dvm_method = dvm_method.unwrap();
                assert_eq!(dvm_method.method_string()
                                     .split("\n")
                                     .zip(code)
                                     .filter(|&(a, b)| a != *b)
                                     .map(|x| println!("{x:?}"))
                                     .count(),
                    0
                );
            }
        }

        #[test]
        fn test_dvm_basic_block() {
            use std::collections::HashMap;

            let methods = HashMap::from([
                (
                    String::from("LDexParserTest;->printMessage()V"),
                    vec![
                        "BB.0-120",
                        "00000000 sget-object v0, java.lang.System->out java.io.PrintStream // field@2",
                        "00000004 new-instance v1, Ljava/lang/StringBuilder; // type@5",
                        "00000008 invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V // method@6",
                        "0000000e const-string v2, \"Field 1: \" // string@4",
                        "00000012 invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "00000018 move-result-object v1",
                        "0000001a iget v2, v3, DexParserTest->field1 int // field@0",
                        "0000001e invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7",
                        "00000024 move-result-object v1",
                        "00000026 invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String; // method@9",
                        "0000002c move-result-object v1",
                        "0000002e invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4",
                        "00000034 sget-object v0, java.lang.System->out java.io.PrintStream // field@2",
                        "00000038 new-instance v1, Ljava/lang/StringBuilder; // type@5",
                        "0000003c invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V // method@6",
                        "00000042 const-string v2, \"Field 2: \" // string@5",
                        "00000046 invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "0000004c move-result-object v1",
                        "0000004e iget-object v2, v3, DexParserTest->field2 java.lang.String // field@1",
                        "00000052 invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "00000058 move-result-object v1",
                        "0000005a invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String; // method@9",
                        "00000060 move-result-object v1",
                        "00000062 invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4",
                        "00000068 sget-object v0, java.lang.System->out java.io.PrintStream // field@2",
                        "0000006c const-string v1, \"This is a test message printed from DexParserTest class.\" // string@19",
                        "00000070 invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4",
                        "00000076 return-void",
                    ]
                ),

                (
                    String::from("LDexParserTest;->main([Ljava/lang/String;)V"),
                    vec![
                        "BB.0-32",
                        "00000000 new-instance v2, LDexParserTest; // type@1",
                        "00000004 invoke-direct {v2}, LDexParserTest;-><init>()V // method@0",
                        "0000000a invoke-direct {v2}, LDexParserTest;->printMessage()V // method@3",
                        "00000010 const/16 v0, 10",
                        "00000014 const/16 v1, 20",
                        "00000018 invoke-direct {v2, v0, v1}, LDexParserTest;->calculateSum(II)I // method@1",
                        "0000001e return-void",
                    ]
                ),

                (
                    String::from("LDexParserTest;->calculateSum(II)I"),
                    vec![
                        "BB.0-94",
                        "00000000 add-int v0, v5, v6",
                        "00000004 sget-object v1, java.lang.System->out java.io.PrintStream // field@2",
                        "00000008 new-instance v2, Ljava/lang/StringBuilder; // type@5",
                        "0000000c invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V // method@6",
                        "00000012 const-string v3, \"Sum of \" // string@18",
                        "00000016 invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "0000001c move-result-object v2",
                        "0000001e invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7",
                        "00000024 move-result-object v5",
                        "00000026 const-string v2, \" and \" // string@0",
                        "0000002a invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "00000030 move-result-object v5",
                        "00000032 invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7",
                        "00000038 move-result-object v5",
                        "0000003a const-string v6, \" is: \" // string@1",
                        "0000003e invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder; // method@8",
                        "00000044 move-result-object v5",
                        "00000046 invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder; // method@7",
                        "0000004c move-result-object v5",
                        "0000004e invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String; // method@9",
                        "00000054 move-result-object v5",
                        "00000056 invoke-virtual {v1, v5}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V // method@4",
                        "0000005c return v0",
                    ]
                ),

                (
                    String::from("LDexParserTest;-><init>()V"),
                    vec![
                        "BB.0-24",
                        "00000000 invoke-direct {v1}, Ljava/lang/Object;-><init>()V // method@5",
                        "00000006 const/16 v0, 42",
                        "0000000a iput v0, v1, DexParserTest->field1 int // field@0",
                        "0000000e const-string v0, \"Hello, Dex Parser!\" // string@6",
                        "00000012 iput-object v0, v1, DexParserTest->field2 java.lang.String // field@1",
                        "00000016 return-void",
                    ]
                ),
            ]);


            let mut context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));
            context.disassemble_dex();
            context.create_dex_analysis(true);
            context.analyze_classes();

            for idx in 0..context.get_number_of_classes() {
                let class = context.get_class_by_id(idx as u16);
                assert!(class.is_some());
                let class = class.unwrap();

                let class_name = class.class_name();
                assert_eq!(class_name, "DexParserTest");

                let class_analysis = context.get_analyzed_class(class_name);
                assert!(class_analysis.is_some());
                let class_analysis = class_analysis.unwrap();

                for method_analysis in class_analysis.methods() {
                    let basic_blocks = method_analysis.basic_blocks();

                    for (block_idx, block) in basic_blocks.blocks().iter().enumerate() {
                        let data = methods.get(method_analysis.full_name());
                        assert!(data.is_some());

                        let data = data.unwrap();
                        assert_eq!(block.block_string()
                                        .split("\n")
                                        .zip(data)
                                        .filter(|&(a, b)| a != *b)
                                        .map(|x| println!("{x:?}"))
                                        .count(),
                            0
                        );
                    }
                }
            }
        }

        #[test]
        fn test_get_analyze_class() {
            let mut context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));
            context.disassemble_dex();
            context.create_dex_analysis(true);
            context.analyze_classes();

            assert_eq!(context.get_number_of_classes(), 1);

            let class_analysis = context.get_analyzed_class("DexParserTest");
            assert!(class_analysis.is_some());
            let class_analysis = class_analysis.unwrap();

            let dvm_class = context.get_class_by_name("DexParserTest");
            assert!(dvm_class.is_some());
            let dvm_class = dvm_class.unwrap();

            let class_analysis_by_hdvmclass = context.get_analyzed_class_by_hdvmclass(&dvm_class);
            assert!(class_analysis_by_hdvmclass.is_some());
            let class_analysis_by_hdvmclass = class_analysis_by_hdvmclass.unwrap();

            assert_eq!(class_analysis.is_external(), class_analysis_by_hdvmclass.is_external());
            assert_eq!(class_analysis.extends(), class_analysis_by_hdvmclass.extends());
            assert_eq!(class_analysis.name(), class_analysis_by_hdvmclass.name());
            assert_eq!(class_analysis.n_of_methods(), class_analysis_by_hdvmclass.n_of_methods());
            assert_eq!(class_analysis.methods(), class_analysis_by_hdvmclass.methods());
            assert_eq!(class_analysis.n_of_fields(), class_analysis_by_hdvmclass.n_of_fields());
            assert_eq!(class_analysis.fields(), class_analysis_by_hdvmclass.fields());
            assert_eq!(class_analysis.n_of_xrefnewinstance(), class_analysis_by_hdvmclass.n_of_xrefnewinstance());
            assert_eq!(class_analysis.xrefnewinstance(), class_analysis_by_hdvmclass.xrefnewinstance());
            assert_eq!(class_analysis.n_of_xrefconstclass(), class_analysis_by_hdvmclass.n_of_xrefconstclass());
            assert_eq!(class_analysis.xrefconstclass(), class_analysis_by_hdvmclass.xrefconstclass());
            assert_eq!(class_analysis.n_of_xrefto(), class_analysis_by_hdvmclass.n_of_xrefto());
            assert_eq!(class_analysis.xrefto(), class_analysis_by_hdvmclass.xrefto());
            assert_eq!(class_analysis.n_of_xreffrom(), class_analysis_by_hdvmclass.n_of_xreffrom());
            assert_eq!(class_analysis.xreffrom(), class_analysis_by_hdvmclass.xreffrom());
        }
    }
}
