//! Analysis data structures

use std::ffi::CStr;
use std::slice::from_raw_parts;

use crate::shuriken;
use crate::disassembler::DvmInstruction;
use crate::dvm_access_flags::{ DvmAccessFlag, DvmAccessFlagType };

/// Type alias for Shuriken's `ref_type`
///
/// Enum that represents the possible reference types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DvmRefType {
    /// New instance of a class
    REF_NEW_INSTANCE = 0x22,
    /// Class is used somewhere
    REF_CLASS_USAGE = 0x1c,
    /// Call of a method from a class
    INVOKE_VIRTUAL = 0x6e,
    /// Call of constructor of super class
    INVOKE_SUPER = 0x6f,
    /// Call a method from a class
    INVOKE_DIRECT = 0x70,
    /// Call a static method from a class
    INVOKE_STATIC = 0x71,
    /// Call an interface method
    INVOKE_INTERFACE = 0x72,
    /// Call of a method from a class with arguments range
    INVOKE_VIRTUAL_RANGE = 0x74,
    /// Call of constructor of super class with arguments range
    INVOKE_SUPER_RANGE = 0x75,
    /// Call a method from a class with arguments range
    INVOKE_DIRECT_RANGE = 0x76,
    /// Call a static method from a class with arguments range
    INVOKE_STATIC_RANGE = 0x77,
    /// Call an interface method with arguments range
    INVOKE_INTERFACE_RANGE = 0x78
}

/// Type alias for Shuriken's `hdvm_class_method_idx_t`
///
/// Cross-ref that contains class, method and instruction address
#[derive(Debug)]
pub struct DvmClassMethodIdx {
    /// Class of the struct
    class: String,
    /// Method of the struct
    method: String,
    /// Index
    idx: u64
}

impl DvmClassMethodIdx {
    pub fn from_ptr(ptr: shuriken::hdvm_class_method_idx_t) -> Self {
        let class = unsafe {
            CStr::from_ptr((*ptr.cls).name_)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let method = unsafe {
            CStr::from_ptr((*ptr.method).full_name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        Self {
            class,
            method,
            idx: ptr.idx as u64
        }
    }
}

/// Type alias for Shuriken's `hdvm_method_idx_t`
///
///  Cross-ref that contains a method and instruction address
#[derive(Debug)]
pub struct DvmMethodIdx {
    /// Method of the XRef
    method: String,
    /// Idx
    idx: u64
}

impl DvmMethodIdx {
    pub fn from_ptr(ptr: shuriken::hdvm_method_idx_t) -> Self {
        let method = unsafe {
            CStr::from_ptr((*ptr.method).full_name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        Self {
            method,
            idx: ptr.idx as u64
        }
    }
}

/// Type alias for Shuriken's `hdvm_class_field_idx_t`
///
///  Cross-ref that contains class, field and instruction address
#[derive(Debug)]
pub struct DvmClassFieldIdx {
    /// Class of the XRef
    class: String,
    /// Field of the XRef
    field: String,
    /// Idx
    idx: u64
}

impl DvmClassFieldIdx {
    pub fn from_ptr(ptr: shuriken::hdvm_class_field_idx_t) -> Self {
        let class = unsafe {
            CStr::from_ptr((*ptr.cls).name_)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let field = unsafe {
            CStr::from_ptr((*ptr.field).name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        Self {
            class,
            field,
            idx: ptr.idx as u64
        }
    }
}

/// Type alias for Shuriken's `hdvm_class_idx_t`
///
/// Cross-ref that contains class and instruction address
#[derive(Debug)]
pub struct DvmClassIdx {
    /// Class of the XRef
    class: String,
    /// Idx
    idx: u64
}

impl DvmClassIdx {
    pub fn from_ptr(ptr: shuriken::hdvm_class_idx_t) -> Self {
        let class = unsafe {
            CStr::from_ptr((*ptr.cls).name_)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        Self {
            class,
            idx: ptr.idx as u64
        }
    }
}

/// Type alias for Shuriken's `hdvm_reftype_method_idx_t`
///
/// Structure that contains a type of reference, a method analysis where reference is and the index
/// in the method where the reference to a class is
#[derive(Debug)]
pub struct DvmRefTypeMethodIdx {
    /// Reference type
    ref_type: DvmRefType,
    /// Method name
    method: String,
    /// Index
    idx: u64
}

impl DvmRefTypeMethodIdx {
    pub fn from_ptr(ptr: shuriken::hdvm_reftype_method_idx_t) -> Self {
        let ref_type = match ptr.reType {
            0x22 => DvmRefType::REF_NEW_INSTANCE,
            0x1c => DvmRefType::REF_CLASS_USAGE,
            0x6e => DvmRefType::INVOKE_VIRTUAL,
            0x6f => DvmRefType::INVOKE_SUPER,
            0x70 => DvmRefType::INVOKE_DIRECT,
            0x71 => DvmRefType::INVOKE_STATIC,
            0x72 => DvmRefType::INVOKE_INTERFACE,
            0x74 => DvmRefType::INVOKE_VIRTUAL_RANGE,
            0x75 => DvmRefType::INVOKE_SUPER_RANGE,
            0x76 => DvmRefType::INVOKE_DIRECT_RANGE,
            0x77 => DvmRefType::INVOKE_STATIC_RANGE,
            0x78 => DvmRefType::INVOKE_INTERFACE_RANGE,
            other => panic!("Invalid ref type: {other:#02X}"),
        };

        let method = unsafe {
            CStr::from_ptr((*ptr.methodAnalysis).full_name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        Self {
            ref_type,
            method,
            idx: ptr.idx
        }
    }
}

/// Type alias for Shuriken's `hdvm_classxref_t`
///
/// Class cross-ref
#[derive(Debug)]
pub struct DvmClassXref {
    /// Class name
    class: String,
    /// Number of methods references
    n_of_reftype_method_idx: usize,
    /// Methods
    methods_xrefs: Vec<DvmRefTypeMethodIdx>
}

impl DvmClassXref {
    pub fn from_ptr(ptr: shuriken::hdvm_classxref_t) -> Self {
        let class = unsafe {
            CStr::from_ptr((*ptr.classAnalysis).name_)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let methods_xrefs = unsafe {
            from_raw_parts(ptr.hdvmReftypeMethodIdx, ptr.n_of_reftype_method_idx)
                .iter()
                .map(|xref| DvmRefTypeMethodIdx::from_ptr(*xref))
                .collect::<Vec<DvmRefTypeMethodIdx>>()
        };

        Self {
            class,
            n_of_reftype_method_idx: ptr.n_of_reftype_method_idx,
            methods_xrefs,
        }
    }
}

/// Type alias for Shuriken's `hdvmbasicblock_t`
///
/// Structure that stores information of a basic block
#[derive(Debug)]
pub struct DvmBasicBlock {
    /// Number of instructions in the block
    n_of_instructions: usize,
    /// Pointer to the instructions in the block
    instructions: Vec<DvmInstruction>,
    /// Is it a try block?
    try_block: bool,
    /// Is it a catch block
    catch_block: bool,
    /// String value of the handler type
    handler_type: String,
    /// Name of the basic block
    name: String,
    /// Whole representation of a basic block in string format
    block_string: String,
}

impl DvmBasicBlock {
    pub fn from_ptr(ptr: shuriken::hdvmbasicblock_t) -> Self {
        let try_block = ptr.try_block == 0;
        let catch_block = ptr.catch_block == 0;

        let instructions = unsafe {
            from_raw_parts(ptr.instructions, ptr.n_of_instructions)
                .iter()
                .map(|ins| DvmInstruction::from_ins(*ins))
                .collect::<Vec<DvmInstruction>>()
        };

        // TODO: in the current test files the handler type contains an invalid
        // reference which leads to a segmentation fault. Need to open an issue
        // upstream to investigate if this is a bug in Shuriken or something else.
        // Issue ref: https://github.com/Shuriken-Group/Shuriken-Analyzer/issues/153
        //
        // let handler_type = unsafe {
        //     CStr::from_ptr(ptr.handler_type)
        //         .to_str()
        //         .expect("Error: string is not valid UTF-8")
        //         .to_string()
        // };
        let handler_type = String::new();

        let name = unsafe {
            CStr::from_ptr(ptr.name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let block_string = unsafe {
            CStr::from_ptr(ptr.block_string)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        Self {
            n_of_instructions: ptr.n_of_instructions,
            instructions,
            try_block,
            catch_block,
            handler_type,
            name,
            block_string
        }
    }
}

/// Type alias for Shuriken's `basic_blocks_t`
///
/// Structure to keep all the basic blocks
#[derive(Debug)]
pub struct DvmBasicBlocks {
    n_of_blocks: usize,
    blocks: Vec<DvmBasicBlock>
}

impl DvmBasicBlocks {
    pub fn from_ptr(ptr: shuriken::basic_blocks_t) -> Self {
        let blocks = unsafe {
            from_raw_parts(ptr.blocks, ptr.n_of_blocks)
                .iter()
                .map(|block| DvmBasicBlock::from_ptr(*block))
                .collect::<Vec<DvmBasicBlock>>()
        };

        Self {
            n_of_blocks: ptr.n_of_blocks,
            blocks
        }
    }
}

/// Type alias for Shuriken's `hdvmfieldanalysis_t`
///
/// Field analysis structure
#[derive(Debug)]
pub struct DvmFieldAnalysis {
    /// Full name of the FieldAnalysis
    name: String,
    /// Number of xrefread
    n_of_xrefread: usize,
    /// xrefread
    xrefread: Vec<DvmClassMethodIdx>,
    /// Number of xrefwrite
    n_of_xrefwrite: usize,
    /// xrefwrite
    xrefwrite: Vec<DvmClassMethodIdx>
}

impl DvmFieldAnalysis {
    pub fn from_ptr(ptr: shuriken::hdvmfieldanalysis_t) -> Self {
        let name = unsafe {
            CStr::from_ptr(ptr.name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let xrefread = unsafe {
            from_raw_parts(ptr.xrefread, ptr.n_of_xrefread)
                .iter()
                .map(|xref| DvmClassMethodIdx::from_ptr(*xref))
                .collect::<Vec<DvmClassMethodIdx>>()
        };

        let xrefwrite = unsafe {
            from_raw_parts(ptr.xrefwrite, ptr.n_of_xrefwrite)
                .iter()
                .map(|xref| DvmClassMethodIdx::from_ptr(*xref))
                .collect::<Vec<DvmClassMethodIdx>>()
        };

        Self {
            name,
            n_of_xrefread: ptr.n_of_xrefread,
            xrefread,
            n_of_xrefwrite: ptr.n_of_xrefwrite,
            xrefwrite
        }
    }
}

/// Type alias for Shuriken's `hdvmstringanalysis_t`
///
/// Structure to keep information about the string analysis [UNUSED FOR NOW]
#[derive(Debug)]
pub struct DvmStringAnalysis(shuriken::hdvmstringanalysis_t);

/// Type alias for Shuriken's `hdvmmethodanalysis_t`
///
/// Structure to keep information about the method analysis
#[derive(Debug)]
pub struct DvmMethodAnalysis {
    /// Name of the method
    name: String,
    /// Descriptor of the method
    descriptor: String,
    /// Full name of the method including class name and descriptor
    full_name: String,
    /// Flag indicating if the method is external or not
    external: bool,
    /// Flag indicating if the method is an android API
    is_android_api: bool,
    /// Access flags
    access_flags: Vec<DvmAccessFlag>,
    /// Class name
    class_name: String,
    /// Basic blocks
    basic_blocks: DvmBasicBlocks,
    /// Number of field read in method
    n_of_xrefread: usize,
    /// Xrefs of field read
    xrefread: Vec<DvmClassFieldIdx>,
    /// Number of field write
    n_of_xrefwrite: usize,
    /// Xrefs of field write
    xrefwrite: Vec<DvmClassFieldIdx>,
    /// Number of xrefto
    n_of_xrefto: usize,
    /// Methods called from the current method
    xrefto: Vec<DvmClassMethodIdx>,
    /// Number of xreffrom
    n_of_xreffrom: usize,
    /// Methods that call the current method
    xreffrom: Vec<DvmClassMethodIdx>,
    /// Number of xrefnewinstance
    n_of_xrefnewinstance: usize,
    /// New instance of the method
    xrefnewinstance: Vec<DvmClassIdx>,
    /// Number of xrefconstclass
    n_of_xrefconstclass: usize,
    /// Use of const class
    xrefconstclass: Vec<DvmClassIdx>,
    /// Cache of method string
    method_string: String,
}

impl DvmMethodAnalysis {
    fn from_ptr(ptr: shuriken::hdvmmethodanalysis_t) -> Self {
        println!("ptr: {ptr:#?}");

        let name = unsafe {
            CStr::from_ptr(ptr.name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let descriptor = unsafe {
            CStr::from_ptr(ptr.descriptor)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let class_name = unsafe {
            CStr::from_ptr(ptr.class_name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let full_name = unsafe {
            CStr::from_ptr(ptr.full_name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let method_string = unsafe {
            CStr::from_ptr(ptr.method_string)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let basic_blocks = unsafe {
            DvmBasicBlocks::from_ptr(*ptr.basic_blocks)
        };

        let xrefread = unsafe {
            from_raw_parts(ptr.xrefread, ptr.n_of_xrefread)
                .iter()
                .map(|xref| DvmClassFieldIdx::from_ptr(*xref))
                .collect::<Vec<DvmClassFieldIdx>>()
        };

        let xrefwrite = unsafe {
            from_raw_parts(ptr.xrefwrite, ptr.n_of_xrefwrite)
                .iter()
                .map(|xref| DvmClassFieldIdx::from_ptr(*xref))
                .collect::<Vec<DvmClassFieldIdx>>()
        };

        let xrefto = unsafe {
            from_raw_parts(ptr.xrefto, ptr.n_of_xrefto)
                .iter()
                .map(|xref| DvmClassMethodIdx::from_ptr(*xref))
                .collect::<Vec<DvmClassMethodIdx>>()
        };

        let xreffrom = unsafe {
            from_raw_parts(ptr.xreffrom, ptr.n_of_xreffrom)
                .iter()
                .map(|xref| DvmClassMethodIdx::from_ptr(*xref))
                .collect::<Vec<DvmClassMethodIdx>>()
        };

        let xrefnewinstance = unsafe {
            from_raw_parts(ptr.xrefnewinstance, ptr.n_of_xrefnewinstance)
                .iter()
                .map(|xref| DvmClassIdx::from_ptr(*xref))
                .collect::<Vec<DvmClassIdx>>()
        };

        let xrefconstclass = unsafe {
            from_raw_parts(ptr.xrefconstclass, ptr.n_of_xrefconstclass)
                .iter()
                .map(|xref| DvmClassIdx::from_ptr(*xref))
                .collect::<Vec<DvmClassIdx>>()
        };

        Self {
            name,
            descriptor,
            full_name,
            external: ptr.external == 0,
            is_android_api: ptr.is_android_api == 0,
            access_flags: DvmAccessFlag::parse(ptr.access_flags, DvmAccessFlagType::Method),
            class_name,
            basic_blocks,
            n_of_xrefread: ptr.n_of_xrefread,
            xrefread,
            n_of_xrefwrite: ptr.n_of_xrefwrite,
            xrefwrite,
            n_of_xrefto: ptr.n_of_xrefto,
            xrefto,
            n_of_xreffrom: ptr.n_of_xreffrom,
            xreffrom,
            n_of_xrefnewinstance: ptr.n_of_xrefnewinstance,
            xrefnewinstance,
            n_of_xrefconstclass: ptr.n_of_xrefconstclass,
            xrefconstclass,
            method_string
        }
    }
}

/// Type alias for Shuriken's `hdvmclassanalysis_t`
///
/// Structure to keep information about the class analysis
#[derive(Debug)]
pub struct DvmClassAnalysis {
    /// is external class?
    is_external: bool,
    /// Name of the class it extends
    extends: String,
    /// name of the class
    name: String,
    /// number of methods
    n_of_methods: usize,
    /// pointer to an array of methods
    methods: Vec<DvmMethodAnalysis>,
    /// number of fields
    n_of_fields: usize,
    /// pointer to an array of fields
    fields: Vec<DvmFieldAnalysis>,
    /// number of xrefnewinstance
    n_of_xrefnewinstance: usize,
    /// New instance of this class
    xrefnewinstance: Vec<DvmMethodIdx>,
    /// number of const class
    n_of_xrefconstclass: usize,
    /// use of const class of this class
    xrefconstclass: Vec<DvmMethodIdx>,
    /// number of xrefto
    n_of_xrefto: usize,
    /// Classes that this class calls
    xrefto: Vec<DvmClassXref>,
    /// number of xreffrom
    n_of_xreffrom: usize,
    /// Classes that call this class
    xreffrom: Vec<DvmClassXref>,
}

impl DvmClassAnalysis {
    pub fn from_ptr(ptr: shuriken::hdvmclassanalysis_t) -> Self {
        let extends = unsafe {
            CStr::from_ptr(ptr.extends_)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let name = unsafe {
            CStr::from_ptr(ptr.name_)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let methods = unsafe {
            from_raw_parts(ptr.methods, ptr.n_of_methods)
                .iter()
                .map(|method| DvmMethodAnalysis::from_ptr(*(*method)))
                .collect::<Vec<DvmMethodAnalysis>>()
        };

        let fields = unsafe {
            from_raw_parts(ptr.fields, ptr.n_of_fields)
                .iter()
                .map(|field| DvmFieldAnalysis::from_ptr(*(*field)))
                .collect::<Vec<DvmFieldAnalysis>>()
        };

        let xrefnewinstance = unsafe {
            from_raw_parts(ptr.xrefnewinstance, ptr.n_of_xrefnewinstance)
                .iter()
                .map(|xref| DvmMethodIdx::from_ptr(*xref))
                .collect::<Vec<DvmMethodIdx>>()
        };

        let xrefconstclass = unsafe {
            from_raw_parts(ptr.xrefconstclass, ptr.n_of_xrefconstclass)
                .iter()
                .map(|xref| DvmMethodIdx::from_ptr(*xref))
                .collect::<Vec<DvmMethodIdx>>()
        };

        let xrefto = unsafe {
            from_raw_parts(ptr.xrefto, ptr.n_of_xrefto)
                .iter()
                .map(|xref| DvmClassXref::from_ptr(*xref))
                .collect::<Vec<DvmClassXref>>()
        };

        let xreffrom = unsafe {
            from_raw_parts(ptr.xreffrom, ptr.n_of_xreffrom)
                .iter()
                .map(|xref| DvmClassXref::from_ptr(*xref))
                .collect::<Vec<DvmClassXref>>()
        };

        DvmClassAnalysis {
            is_external: ptr.is_external == 0,
            extends,
            name,
            n_of_methods: ptr.n_of_methods,
            methods,
            n_of_fields: ptr.n_of_fields,
            fields,
            n_of_xrefnewinstance: ptr.n_of_xrefnewinstance,
            xrefnewinstance,
            n_of_xrefconstclass: ptr.n_of_xrefconstclass,
            xrefconstclass,
            n_of_xrefto: ptr.n_of_xrefto,
            xrefto,
            n_of_xreffrom: ptr.n_of_xreffrom,
            xreffrom,
        }
    }
}
