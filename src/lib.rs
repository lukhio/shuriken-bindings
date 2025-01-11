#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#![allow(dead_code)]
#![allow(unused_variables)]

use std::path::PathBuf;
use std::ffi::CString;

mod shuriken {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/shuriken_core.rs"));
}

/// Type alias for Shuriken's `hDexContext`
pub struct DexContext(shuriken::hDexContext);
/// Type alias for Shuriken's `hApkContext`
pub struct ApkContext(shuriken::hApkContext);

// --------------------------- Parser Data ---------------------------

/// Type alias for Shuriken's `htype_e`
///
/// DEX types of the DVM we have by default fundamental, classes and array
pub struct DexTypes(shuriken::htype_e);

/// Type alias for Shuriken's `hfundamental_e`
///
/// Enum with the basic DEX types
pub struct DexBasicTypes(shuriken::hfundamental_e);

/// Type alias for Shuriken's `access_flags_e`
///
/// Access flags from the Dalvik Virtual Machine
pub struct DvmAccessFlags(shuriken::access_flags_e);

/// Type alias for Shuriken's `hdvmfield_t`
///
/// Structure which keeps information from a field this can be accessed from the class data
pub struct DvmField(shuriken::hdvmfield_t);

/// Type alias for Shuriken's `hdvmmethod_t`
///
/// Structure which keeps information from a method this can be accessed from the class data
pub struct DvmMethod(shuriken::hdvmmethod_t);

/// Type alias for Shuriken's `hdvmclass_t`
///
/// Structure representing the classes in the DEX file
pub struct DvmClass(shuriken::hdvmclass_t);

// --------------------------- Disassembler Data ---------------------------

/// Type alias for Shuriken's `dexinsttype_e`
///
/// Instruction types from the Dalvik Virtual Machine
pub struct DexInstType(shuriken::dexinsttype_e);

/// Type alias for Shuriken's `hdvminstruction_t`
///
/// Structure for an instruction in the dalvik virtual machine
pub struct DvmInstruction(shuriken::hdvminstruction_t);

/// Type alias for Shuriken's `dvmhandler_data_t`
///
/// Structure that keeps information about a handler
pub struct DvmHandlerData(shuriken::dvmhandler_data_t);

/// Type alias for Shuriken's `dvmexceptions_data_t`
///
/// Structure with the information from the exceptions in the code
pub struct DvmException(shuriken::dvmexceptions_data_t);

/// Type alias for Shuriken's `dvmdisassembled_method_t`
///
/// Structure that represents a disassembled method from the dalvik file
pub struct DvmDisassembledMethod(shuriken::dvmdisassembled_method_t);

// --------------------------- Analysis Data ---------------------------

/// Type alias for Shuriken's `ref_type`
///
/// Enum that represents the possible reference types
pub struct DvmRefType(shuriken::ref_type);

/// Type alias for Shuriken's `hdvm_class_method_idx_t`
///
/// Cross-ref that contains class, method and instruction address
pub struct DvmClassMethodIdx(shuriken::hdvm_class_method_idx_t);

/// Type alias for Shuriken's `hdvm_method_idx_t`
///
///  Cross-ref that contains a method and instruction address
pub struct DvmMethodIdx(shuriken::hdvm_method_idx_t);

/// Type alias for Shuriken's `hdvm_class_field_idx_t`
///
///  Cross-ref that contains class, field and instruction address
pub struct DvmClassFieldIdx(shuriken::hdvm_class_field_idx_t);

/// Type alias for Shuriken's `hdvm_class_idx_t`
///
/// Cross-ref that contains class and instruction address
pub struct DvmClassIdx(shuriken::hdvm_class_idx_t);

/// Type alias for Shuriken's `hdvm_reftype_method_idx_t`
///
/// Structure that contains a type of reference, a method analysis where reference is and the index
/// in the method where the reference to a class is
pub struct DvmRefTypeMethodIdx(shuriken::hdvm_reftype_method_idx_t);

/// Type alias for Shuriken's `hdvm_classxref_t`
///
/// Class cross-ref
pub struct DvmClassXRef(shuriken::hdvm_classxref_t);

/// Type alias for Shuriken's `hdvmbasicblock_t`
///
/// Structure that stores information of a basic block
pub struct DvmBasicBlock(shuriken::hdvmbasicblock_t);

/// Type alias for Shuriken's `basic_blocks_t`
///
/// Structure to keep all the basic blocks
pub struct BasicBlocks(shuriken::basic_blocks_t);

/// Type alias for Shuriken's `hdvmfieldanalysis_t`
///
/// Field analysis structure
pub struct DvmFieldAnalysis(shuriken::hdvmfieldanalysis_t);

/// Type alias for Shuriken's `hdvmstringanalysis_t`
///
/// Structure to keep information about the string analysis [UNUSED FOR NOW]
pub struct DvmStringAnalysis(shuriken::hdvmstringanalysis_t);

/// Type alias for Shuriken's `hdvmmethodanalysis_t`
///
/// Structure to keep information about the method analysis
pub struct DvmMethodAnalysis(shuriken::hdvmmethodanalysis_t);

/// Type alias for Shuriken's `hdvmclassanalysis_t`
///
/// Structure to keep information about the class analysis
pub struct DvmClassAnalysis(shuriken::hdvmclassanalysis_t);

// --------------------------- Parser API ---------------------------

impl Drop for DexContext {
    fn drop(&mut self) {
        unsafe {
                shuriken::destroy_dex(self.0);
        }
    }
}

impl DexContext {
    /// Main method from the DEX core API
    ///
    /// Parse a DEX file and return a DEX context
    /// TODO: make sure we correctly handle non-ascii paths
    pub fn parse_dex(filepath: &PathBuf) -> Self {
        let c_str = CString::new(filepath.clone().into_os_string().into_string().unwrap()).unwrap();
        let c_world = c_str.as_ptr();
        unsafe {
            DexContext(shuriken::parse_dex(c_world))
        }
    }

    /// Get the number of strings in the DEX file
    pub fn get_number_of_strings(&self) -> usize {
        unsafe {
            shuriken::get_number_of_strings(self.0)
        }
    }

    /// Get a string given its ID
    ///
    /// TODO: need to research how to properly take ownership of this string
    /// Maybe we can loop through the bytes and build a `String` like this?
    pub fn get_string_by_id(&self, string_id: usize) -> String {
        todo!()
    }

    /// Get the number of classes in the DEX file
    pub fn get_number_of_classes(&self) -> usize {
        unsafe {
            shuriken::get_number_of_classes(self.0).into()
        }
    }

    /// Get a class structure given an ID
    pub fn get_class_by_id(&self, id: u16) -> DvmClass {
        todo!();
    }

    /// Get a class structure given a class name
    pub fn get_class_by_name(&self, class_name: String) -> DvmClass {
        todo!();
    }

    /// Get a method structure given a full dalvik name.
    pub fn get_method_by_name(&self, method_name: String) -> DvmMethod {
        todo!();
    }


    // --------------------------- Disassembler API ---------------------------

    /// Disassemble a DEX file and generate an internal DexDisassembler
    pub fn disassemble_dex(&self) {
        todo!();
    }

    /// Get a method structure given a full dalvik name.
    pub fn get_disassembled_method(&self, method_name: String) -> DvmDisassembledMethod {
        todo!();
    }

    // --------------------------- Analysis API ---------------------------

    /// Create a DEX analysis object inside of &self
    ///
    /// Optionally this function can create the cross-refs. In that case the analysis will take longer.
    /// To obtain the analysis, you must also call [`analyze_classes`](fn.analyze_classes.html)
    pub fn create_dex_analysis(&self, create_xrefs: bool) {
        todo!();
    }

    /// Analyze the classes, add fields and methods into the classes, optionally create the xrefs
    pub fn analyze_classes(&self) {
        todo!();
    }

    /// Obtain a `DvmClassAnalysis` given a `DvmClass`
    pub fn get_analyzed_class_by_hdvmclass(&self, class: &DvmClass ) -> &DvmClassAnalysis {
        todo!();
    }

    /// Obtain a `DvmClassAnalysis` given a class name
    pub fn get_analyzed_class(&self, class_name: &str) -> &DvmClassAnalysis {
        todo!();
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
    use super::*;
    use std::fs;


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
    fn test_nb_strings_dex() {
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
}
