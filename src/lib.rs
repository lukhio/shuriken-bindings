#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(dead_code)]

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

// --------------------------- 
//
impl Drop for DexContext {
    fn drop(&mut self) {
        unsafe {
                shuriken::destroy_dex(self.0);
        }
    }
}

// --------------------------- Parser API ---------------------------

/// Main method from the DEX core API
///
/// Parse a DEX file and return a DEX context
/// TODO: change for pathbuf
pub fn parse_dex(filepath: String) -> DexContext {
    let c_str = CString::new(filepath).unwrap();
    let c_world = c_str.as_ptr();
    unsafe {
        DexContext(shuriken::parse_dex(c_world))
    }
}

/// Get number of strings in the DEX file
pub fn get_number_of_strings(context: DexContext) -> usize {
    unsafe {
        shuriken::get_number_of_strings(context.0)
    }
}
