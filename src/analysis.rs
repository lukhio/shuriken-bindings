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
#[derive(Debug, PartialEq)]
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

    /// Return a reference to the class of the struct
    pub fn class(&self) -> &str {
        &self.class
    }

    /// Return a reference to the method of the struct
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Return the index
    pub fn idx(&self) -> u64 {
        self.idx
    }
}

/// Type alias for Shuriken's `hdvm_method_idx_t`
///
///  Cross-ref that contains a method and instruction address
#[derive(Debug, PartialEq)]
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

    /// Return a reference to the method of the XRef
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Return the idx
    pub fn idx(&self) -> u64 {
        self.idx
    }
}

/// Type alias for Shuriken's `hdvm_class_field_idx_t`
///
///  Cross-ref that contains class, field and instruction address
#[derive(Debug, PartialEq)]
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

    /// Return a reference to the class of the XRef
    pub fn class(&self) -> &str {
        &self.class
    }

    /// Return a reference to the field of the XRef
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Return the idx
    pub fn idx(&self) -> u64 {
        self.idx
    }
}

/// Type alias for Shuriken's `hdvm_class_idx_t`
///
/// Cross-ref that contains class and instruction address
#[derive(Debug, PartialEq)]
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

    /// Return a reference to the class of the XRef
    pub fn class(&self) -> &str {
        &self.class
    }

    /// Return the idx
    pub fn idx(&self) -> u64 {
        self.idx
    }
}

/// Type alias for Shuriken's `hdvm_reftype_method_idx_t`
///
/// Structure that contains a type of reference, a method analysis where reference is and the index
/// in the method where the reference to a class is
#[derive(Debug, PartialEq)]
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

    /// Return the reference type
    pub fn ref_type(&self) -> DvmRefType {
        self.ref_type
    }

    /// Return a reference to the method name
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Return the index
    pub fn idx(&self) -> u64 {
        self.idx
    }
}

/// Type alias for Shuriken's `hdvm_classxref_t`
///
/// Class cross-ref
#[derive(Debug, PartialEq)]
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

    /// Return a reference to the class name
    pub fn class(&self) -> &str {
        &self.class
    }

    /// Return the number of methods references
    pub fn n_of_reftype_method_idx(&self) -> usize {
        self.n_of_reftype_method_idx
    }

    /// Return a reference to the methods
    pub fn methods_xrefs(&self) -> &[DvmRefTypeMethodIdx] {
        &self.methods_xrefs
    }
}

/// Type alias for Shuriken's `hdvmbasicblock_t`
///
/// Structure that stores information of a basic block
#[derive(Debug, PartialEq)]
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

    /// Return the number of instructions in the block
    pub fn n_of_instructions(&self) -> usize {
        self.n_of_instructions
    }

    /// Return a reference to the pointer to the instructions in the block
    pub fn instructions(&self) -> &[DvmInstruction] {
        &self.instructions
    }

    /// Return the is it a try block?
    pub fn try_block(&self) -> bool {
        self.try_block
    }

    /// Return the is it a catch block
    pub fn catch_block(&self) -> bool {
        self.catch_block
    }

    /// Return a reference to the string value of the handler type
    pub fn handler_type(&self) -> &str {
        &self.handler_type
    }

    /// Return a reference to the name of the basic block
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return a reference to the whole representation of a basic block in string format
    pub fn block_string(&self) -> &str {
        &self.block_string
    }

}

/// Type alias for Shuriken's `basic_blocks_t`
///
/// Structure to keep all the basic blocks
#[derive(Debug, PartialEq)]
pub struct DvmBasicBlocks {
    /// Number of basic blocks
    n_of_blocks: usize,
    /// Vector of basic blocks
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

    /// Return the number of basic blocks
    pub fn n_of_blocks(&self) -> usize {
        self.n_of_blocks
    }

    /// Return a reference to the vector of basic blocks
    pub fn blocks(&self) -> &[DvmBasicBlock] {
        &self.blocks
    }
}

/// Type alias for Shuriken's `hdvmfieldanalysis_t`
///
/// Field analysis structure
#[derive(Debug, PartialEq)]
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

    /// Return a reference to the full name of the FieldAnalysis
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the number of xrefread
    pub fn n_of_xrefread(&self) -> usize {
        self.n_of_xrefread
    }

    /// Return a reference to the xrefread
    pub fn xrefread(&self) -> &[DvmClassMethodIdx] {
        &self.xrefread
    }

    /// Return the number of xrefwrite
    pub fn n_of_xrefwrite(&self) -> usize {
        self.n_of_xrefwrite
    }

    /// Return a reference to the xrefwrite
    pub fn xrefwrite(&self) -> &[DvmClassMethodIdx] {
        &self.xrefwrite
    }
}

/// Type alias for Shuriken's `hdvmstringanalysis_t`
///
/// Structure to keep information about the string analysis.
/// Note: marked as unused in Shuriken as of commit 80443a3 so not implemented here either.
#[derive(Debug, PartialEq)]
pub struct DvmStringAnalysis {
    /// Value of the string
    value: String,
    /// Number of xref from
    n_of_xreffrom: usize,
    /// Xrefs from
    xreffrom: Vec<DvmClassMethodIdx>,
}

impl DvmStringAnalysis {
    pub fn from_ptr(ptr: shuriken::hdvmstringanalysis_t) -> Self {
        let value = unsafe {
            CStr::from_ptr(ptr.value)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let xreffrom = unsafe {
            from_raw_parts(ptr.xreffrom, ptr.n_of_xreffrom)
                .iter()
                .map(|xref| DvmClassMethodIdx::from_ptr(*xref))
                .collect::<Vec<DvmClassMethodIdx>>()
        };

        Self {
            value,
            n_of_xreffrom: ptr.n_of_xreffrom,
            xreffrom
        }
    }
}

/// Type alias for Shuriken's `hdvmmethodanalysis_t`
///
/// Structure to keep information about the method analysis
#[derive(Debug, PartialEq)]
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
    pub fn from_ptr(ptr: shuriken::hdvmmethodanalysis_t) -> Self {
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

    /// Return a reference to the name of the method
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return a reference to the descriptor of the method
    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }

    /// Return a reference to the full name of the method including class name and descriptor
    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    /// Return the flag indicating if the method is external or not
    pub fn external(&self) -> bool {
        self.external
    }

    /// Return the flag indicating if the method is an android API
    pub fn is_android_api(&self) -> bool {
        self.is_android_api
    }

    /// Return a reference to the access flags
    pub fn access_flags(&self) -> &[DvmAccessFlag] {
        &self.access_flags
    }

    /// Return a reference to the class name
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Return a reference to the basic blocks
    pub fn basic_blocks(&self) -> &DvmBasicBlocks {
        &self.basic_blocks
    }

    /// Return the number of field read in method
    pub fn n_of_xrefread(&self) -> usize {
        self.n_of_xrefread
    }

    /// Return a reference to the xrefs of field read
    pub fn xrefread(&self) -> &[DvmClassFieldIdx] {
        &self.xrefread
    }

    /// Return the number of field write
    pub fn n_of_xrefwrite(&self) -> usize {
        self.n_of_xrefwrite
    }

    /// Return a reference to the xrefs of field write
    pub fn xrefwrite(&self) -> &[DvmClassFieldIdx] {
        &self.xrefwrite
    }

    /// Return the number of xrefto
    pub fn n_of_xrefto(&self) -> usize {
        self.n_of_xrefto
    }

    /// Return a reference to the methods called from the current method
    pub fn xrefto(&self) -> &[DvmClassMethodIdx] {
        &self.xrefto
    }

    /// Return the number of xreffrom
    pub fn n_of_xreffrom(&self) -> usize {
        self.n_of_xreffrom
    }

    /// Return a reference to the methods that call the current method
    pub fn xreffrom(&self) -> &[DvmClassMethodIdx] {
        &self.xreffrom
    }

    /// Return the number of xrefnewinstance
    pub fn n_of_xrefnewinstance(&self) -> usize {
        self.n_of_xrefnewinstance
    }

    /// Return a reference to the new instance of the method
    pub fn xrefnewinstance(&self) -> &[DvmClassIdx] {
        &self.xrefnewinstance
    }

    /// Return the number of xrefconstclass
    pub fn n_of_xrefconstclass(&self) -> usize {
        self.n_of_xrefconstclass
    }

    /// Return a reference to the use of const class
    pub fn xrefconstclass(&self) -> &[DvmClassIdx] {
        &self.xrefconstclass
    }

    /// Return a reference to the cache of method string
    pub fn method_string(&self) -> &str {
        &self.method_string
    }
}

/// Type alias for Shuriken's `hdvmclassanalysis_t`
///
/// Structure to keep information about the class analysis
#[derive(Debug, PartialEq)]
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

    /// Return the is external class?
    pub fn is_external(&self) -> bool {
        self.is_external
    }

    /// Return a reference to the name of the class it extends
    pub fn extends(&self) -> &str {
        &self.extends
    }

    /// Return a reference to the name of the class
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the number of methods
    pub fn n_of_methods(&self) -> usize {
        self.n_of_methods
    }

    /// Return a reference to the pointer to an array of methods
    pub fn methods(&self) -> &[DvmMethodAnalysis] {
        &self.methods
    }

    /// Return the number of fields
    pub fn n_of_fields(&self) -> usize {
        self.n_of_fields
    }

    /// Return a reference to the pointer to an array of fields
    pub fn fields(&self) -> &[DvmFieldAnalysis] {
        &self.fields
    }

    /// Return the number of xrefnewinstance
    pub fn n_of_xrefnewinstance(&self) -> usize {
        self.n_of_xrefnewinstance
    }

    /// Return a reference to the new instance of this class
    pub fn xrefnewinstance(&self) -> &[DvmMethodIdx] {
        &self.xrefnewinstance
    }

    /// Return the number of const class
    pub fn n_of_xrefconstclass(&self) -> usize {
        self.n_of_xrefconstclass
    }

    /// Return a reference to the use of const class of this class
    pub fn xrefconstclass(&self) -> &[DvmMethodIdx] {
        &self.xrefconstclass
    }

    /// Return the number of xrefto
    pub fn n_of_xrefto(&self) -> usize {
        self.n_of_xrefto
    }

    /// Return a reference to the classes that this class calls
    pub fn xrefto(&self) -> &[DvmClassXref] {
        &self.xrefto
    }

    /// Return the number of xreffrom
    pub fn n_of_xreffrom(&self) -> usize {
        self.n_of_xreffrom
    }

    /// Return a reference to the classes that call this class
    pub fn xreffrom(&self) -> &[DvmClassXref] {
        &self.xreffrom
    }
}
