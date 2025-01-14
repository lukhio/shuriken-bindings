#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#![allow(dead_code)]
#![allow(unused_variables)]

pub mod dvm_access_flags;

use std::path::Path;
use std::ffi::{ CStr, CString };
use std::slice::from_raw_parts;
use std::collections::HashMap;

use crate::dvm_access_flags::{ DvmAccessFlag, DvmAccessFlagType };

mod shuriken {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/shuriken_core.rs"));
}

/// Type alias for Shuriken's `hDexContext`
#[derive(Debug)]
pub struct DexContext {
    ptr: shuriken::hDexContext,
    class_ptrs: HashMap<String, *mut shuriken::hdvmclass_t>,
    method_ptrs: HashMap<String, *mut shuriken::hdvmmethod_t>,
}

/// Type alias for Shuriken's `hApkContext`
#[derive(Debug)]
pub struct ApkContext(shuriken::hApkContext);

// --------------------------- Parser Data ---------------------------

/// Type alias for Shuriken's `htype_e`
///
/// DEX types of the DVM we have by default fundamental, classes and array
#[derive(Debug, PartialEq)]
pub enum DexTypes {
    /// Fundamental type (int, float...)
    Fundamental,
    /// User defined class
    Class,
    /// Array type
    Array,
    /// Maybe wrong?
    Unknown
}

/// Type alias for Shuriken's `hfundamental_e`
///
/// Enum with the basic DEX types
#[derive(Debug, PartialEq)]
pub enum DexBasicTypes {
    Boolean,
    Byte,
    Char,
    Double,
    Float,
    Int,
    Long,
    Short,
    Void,
    FundamentalNone
}

/// Type alias for Shuriken's `hdvmfield_t`
///
/// Structure which keeps information from a field this can be accessed from the class data
#[derive(Debug)]
pub struct DvmField {
    /// Name of the class the field belong to
    class_name: String,
    /// Name of the field
    name: String,
    /// Type of the field
    field_type: DexTypes,
    /// If `field_type` is `Fundamental`
    ///
    /// Note: if `field_type` is `Array` and the base type is
    /// a fundamental value, it contains that value
    fundamental_value: DexBasicTypes,
    /// String value of the type
    type_value: String,
    /// Access flags of the field
    access_flags: Vec<DvmAccessFlag>
}

impl DvmField {
    /// Convert an `hdvmfield_t` into a `DvmField`
    unsafe fn from_hdvmfield_t(field: shuriken::hdvmfield_t) -> Self {
        let class_name = CStr::from_ptr(field.class_name)
            .to_str()
            .expect("Error: string is not valid UTF-8")
            .to_string();

        let name = CStr::from_ptr(field.name)
            .to_str()
            .expect("Error: string is not valid UTF-8")
            .to_string();

        let type_value = CStr::from_ptr(field.type_value)
            .to_str()
            .expect("Error: string is not valid UTF-8")
            .to_string();

        let access_flags = DvmAccessFlag::parse(
            field.access_flags as u32,
            DvmAccessFlagType::Class
        );

        let field_type = match field.type_ {
            0 => DexTypes::Fundamental,
            1 => DexTypes::Class,
            2 => DexTypes::Array,
            _ => DexTypes::Unknown,
        };

        let fundamental_value = if field_type == DexTypes::Fundamental {
            match field.fundamental_value {
                0 => DexBasicTypes::Boolean,
                1 => DexBasicTypes::Byte,
                2 => DexBasicTypes::Char,
                3 => DexBasicTypes::Double,
                4 => DexBasicTypes::Float,
                5 => DexBasicTypes::Int,
                6 => DexBasicTypes::Long,
                7 => DexBasicTypes::Short,
                8 => DexBasicTypes::Void,
                _ => panic!("Invalid fundamental value")
            }
        } else {
            DexBasicTypes::FundamentalNone
        };

        Self {
            class_name,
            name,
            field_type,
            fundamental_value,
            type_value,
            access_flags
        }
    }
}

/// Type alias for Shuriken's `hdvmmethod_t`
///
/// Structure which keeps information from a method this can be accessed from the class data
#[derive(Debug, PartialEq)]
pub struct DvmMethod {
    class_name: String,
    method_name: String,
    prototype: String,
    access_flags: Vec<DvmAccessFlag>,
    code_size: usize,
    code: Vec<u8>,
    dalvik_name: String,
    demangled_name: String
}

impl DvmMethod {
    /// Convert an `hdvmmethod_t` into a `DvmMethod`
    unsafe fn from_hdvmmethod_t(method: shuriken::hdvmmethod_t) -> Self {
        let class_name = CStr::from_ptr(method.class_name)
            .to_str()
            .expect("Error: string is not valid UTF-8")
            .to_string();

        let method_name = CStr::from_ptr(method.method_name)
            .to_str()
            .expect("Error: string is not valid UTF-8")
            .to_string();

        let prototype = CStr::from_ptr(method.prototype)
            .to_str()
            .expect("Error: string is not valid UTF-8")
            .to_string();

        let access_flags = DvmAccessFlag::parse(method.access_flags.into(), DvmAccessFlagType::Method);

        let dalvik_name = CStr::from_ptr(method.dalvik_name)
            .to_str()
            .expect("Error: string is not valid UTF-8")
            .to_string();

        let demangled_name = CStr::from_ptr(method.demangled_name)
            .to_str()
            .expect("Error: string is not valid UTF-8")
            .to_string();

        let code = from_raw_parts(method.code, method.code_size as usize).to_vec();

        DvmMethod {
            class_name,
            method_name,
            prototype,
            access_flags,
            code_size: method.code_size as usize,
            code,
            dalvik_name,
            demangled_name
        }
    }
}


/// Type alias for Shuriken's `hdvmclass_t`
///
/// Structure representing the classes in the DEX file
/// TODO: build the arrays in this. Right now we just have pointers which is not convinient
#[derive(Debug)]
pub struct DvmClass {
    class_name: String,
    super_class: String,
    source_file: String,
    access_flags: Vec<DvmAccessFlag>,
    direct_methods_size: usize,
    direct_methods: Vec<DvmMethod>,
    virtual_methods_size: usize,
    virtual_methods: Vec<DvmMethod>,
    instance_fields_size: usize,
    instance_fields: Vec<DvmField>,
    static_fields_size: usize,
    static_fields: Vec<DvmField>
}

impl DvmClass {
    fn from_hdvmclass_t(dvm_class: shuriken::hdvmclass_t) -> Self {
        let class_name = unsafe {
            CStr::from_ptr(dvm_class.class_name)
                 .to_str()
                 .expect("Error: string is not valid UTF-8")
                 .to_string()
        };

        let super_class = unsafe {
            CStr::from_ptr(dvm_class.super_class)
                 .to_str()
                 .expect("Error: string is not valid UTF-8")
                 .to_string()
        };

        let source_file = unsafe {
            CStr::from_ptr(dvm_class.source_file)
                 .to_str()
                 .expect("Error: string is not valid UTF-8")
                 .to_string()
        };

        let access_flags = DvmAccessFlag::parse(
            dvm_class.access_flags as u32,
            DvmAccessFlagType::Class
        );

        let direct_methods = unsafe {
            from_raw_parts(
                dvm_class.direct_methods,
                dvm_class.direct_methods_size.into()
            )
                .iter()
                .map(|method| DvmMethod::from_hdvmmethod_t(*method))
                .collect::<Vec<DvmMethod>>()
        };

        let virtual_methods = unsafe {
            from_raw_parts(
                dvm_class.virtual_methods,
                dvm_class.virtual_methods_size.into()
            )
                .iter()
                .map(|method| DvmMethod::from_hdvmmethod_t(*method))
                .collect::<Vec<DvmMethod>>()
        };

        let instance_fields =  unsafe {
            from_raw_parts(
                dvm_class.instance_fields,
                dvm_class.instance_fields_size.into()
            )
                .iter()
                .map(|field| DvmField::from_hdvmfield_t(*field))
                .collect::<Vec<DvmField>>()
        };

        let static_fields =  unsafe {
            from_raw_parts(
                dvm_class.static_fields,
                dvm_class.static_fields_size.into()
            )
                .iter()
                .map(|field| DvmField::from_hdvmfield_t(*field))
                .collect::<Vec<DvmField>>()
        };

        DvmClass {
            class_name,
            super_class,
            source_file,
            access_flags,
            direct_methods_size: dvm_class.direct_methods_size as usize,
            direct_methods,
            virtual_methods_size: dvm_class.virtual_methods_size as usize,
            virtual_methods,
            instance_fields_size: dvm_class.instance_fields_size as usize,
            instance_fields,
            static_fields_size: dvm_class.static_fields_size as usize,
            static_fields
        }
    }
}

// --------------------------- Disassembler Data ---------------------------

/// Type alias for Shuriken's `dexinsttype_e`
///
/// Instruction types from the Dalvik Virtual Machine
#[derive(Debug)]
pub enum DexInstType {
    DexInstruction00x,
    DexInstruction10x,
    DexInstruction12x,
    DexInstruction11n,
    DexInstruction11x,
    DexInstruction10t,
    DexInstruction20t,
    DexInstruction20bc,
    DexInstruction22x,
    DexInstruction21t,
    DexInstruction21s,
    DexInstruction21h,
    DexInstruction21c,
    DexInstruction23x,
    DexInstruction22b,
    DexInstruction22t,
    DexInstruction22s,
    DexInstruction22c,
    DexInstruction22cs,
    DexInstruction30t,
    DexInstruction32x,
    DexInstruction31i,
    DexInstruction31t,
    DexInstruction31c,
    DexInstruction35c,
    DexInstruction3rc,
    DexInstruction45cc,
    DexInstruction4rcc,
    DexInstruction51l,
    DexPackedSwitch,
    DexSparseSwitch,
    DexFillArrayData,
    DexDalvikIncorrect,
    DexNoneOp     // = 99,
}

/// Type alias for Shuriken's `hdvminstruction_t`
///
/// Structure for an instruction in the dalvik virtual machine
#[derive(Debug)]
pub struct DvmInstruction {
    instruction_type: DexInstType,
    instruction_length: usize,
    address: u64,
    // TODO: replace with a enum of all opcodes maybe?
    op: u32,
    disassembly: String
}

impl DvmInstruction {
    fn from_ins(ins: shuriken::hdvminstruction_t) -> Self {
        let instruction_type = match ins.instruction_type {
            0  => DexInstType::DexInstruction00x,
            1  => DexInstType::DexInstruction10x,
            2  => DexInstType::DexInstruction12x,
            3  => DexInstType::DexInstruction11n,
            4  => DexInstType::DexInstruction11x,
            5  => DexInstType::DexInstruction10t,
            6  => DexInstType::DexInstruction20t,
            7  => DexInstType::DexInstruction20bc,
            8  => DexInstType::DexInstruction22x,
            9  => DexInstType::DexInstruction21t,
            10 => DexInstType::DexInstruction21s,
            11 => DexInstType::DexInstruction21h,
            12 => DexInstType::DexInstruction21c,
            13 => DexInstType::DexInstruction23x,
            14 => DexInstType::DexInstruction22b,
            15 => DexInstType::DexInstruction22t,
            16 => DexInstType::DexInstruction22s,
            17 => DexInstType::DexInstruction22c,
            18 => DexInstType::DexInstruction22cs,
            19 => DexInstType::DexInstruction30t,
            20 => DexInstType::DexInstruction32x,
            21 => DexInstType::DexInstruction31i,
            22 => DexInstType::DexInstruction31t,
            23 => DexInstType::DexInstruction31c,
            24 => DexInstType::DexInstruction35c,
            25 => DexInstType::DexInstruction3rc,
            26 => DexInstType::DexInstruction45cc,
            27 => DexInstType::DexInstruction4rcc,
            28 => DexInstType::DexInstruction51l,
            29 => DexInstType::DexPackedSwitch,
            30 => DexInstType::DexSparseSwitch,
            31 => DexInstType::DexFillArrayData,
            99 => DexInstType::DexNoneOp,
            _  => DexInstType::DexDalvikIncorrect,
        };

        let disassembly = unsafe {
            CStr::from_ptr(ins.disassembly)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        DvmInstruction {
            instruction_type,
            instruction_length: ins.instruction_length as usize,
            address: ins.address,
            op: ins.op,
            disassembly
        }
    }
}

/// Type alias for Shuriken's `dvmhandler_data_t`
///
/// Structure that keeps information about a handler
#[derive(Debug)]
pub struct DvmHandlerData {
    handler_type: String,
    handler_start_addr: u64
}

impl DvmHandlerData {
    fn from_ptr(ptr: shuriken::dvmhandler_data_t) -> Self {
        let handler_type = unsafe {
            CStr::from_ptr(ptr.handler_type)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        Self {
            handler_type,
            handler_start_addr: ptr.handler_start_addr
        }
    }
}

/// Type alias for Shuriken's `dvmexceptions_data_t`
///
/// Structure with the information from the exceptions in the code
#[derive(Debug)]
pub struct DvmException {
    try_value_start_addr: u64,
    try_value_end_addr: u64,
    n_of_handlers: usize,
    handlers: Vec<DvmHandlerData>
}

impl DvmException {
    fn from_ptr(ptr: shuriken::dvmexceptions_data_t) -> Self {
        let handlers = unsafe {
            from_raw_parts(ptr.handler, ptr.n_of_handlers)
                .iter()
                .map(|handler| DvmHandlerData::from_ptr(*handler))
                .collect::<Vec<DvmHandlerData>>()
        };

        Self {
            try_value_start_addr: ptr.try_value_start_addr,
            try_value_end_addr: ptr.try_value_end_addr,
            n_of_handlers: ptr.n_of_handlers,
            handlers
        }
    }
}

/// Type alias for Shuriken's `dvmdisassembled_method_t`
///
/// Structure that represents a disassembled method from the dalvik file
#[derive(Debug)]
pub struct DvmDisassembledMethod {
    // TODO: replace with ref maybe?
    method_id: DvmMethod,
    n_of_registers: usize,
    n_of_exceptions: usize,
    exception_information: Vec<DvmException>,
    n_of_instructions: usize,
    instructions: Vec<DvmInstruction>,
    method_string: String,
}

impl DvmDisassembledMethod {
    fn from_dvmdisassembled_method_t(
        dvm_disas: shuriken::dvmdisassembled_method_t,
        dvm_method: DvmMethod
    ) -> Self
    {

        let method_string = unsafe {
            CStr::from_ptr(dvm_disas.method_string)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let exception_information = unsafe {
            from_raw_parts(dvm_disas.exception_information, dvm_disas.n_of_exceptions)
                .iter()
                .map(|exc| DvmException::from_ptr(*exc))
                .collect::<Vec<DvmException>>()
        };

        let instructions = unsafe {
            from_raw_parts(dvm_disas.instructions, dvm_disas.n_of_instructions)
                .iter()
                .map(|ins| DvmInstruction::from_ins(*ins))
                .collect::<Vec<DvmInstruction>>()
        };

        Self {
            method_id: dvm_method,
            n_of_registers: dvm_disas.n_of_registers.into(),
            n_of_exceptions: dvm_disas.n_of_exceptions,
            exception_information,
            n_of_instructions: dvm_disas.n_of_instructions,
            instructions,
            method_string
        }
    }
}

// --------------------------- Analysis Data ---------------------------

/// Type alias for Shuriken's `ref_type`
///
/// Enum that represents the possible reference types
#[derive(Debug)]
pub struct DvmRefType(shuriken::ref_type);

/// Type alias for Shuriken's `hdvm_class_method_idx_t`
///
/// Cross-ref that contains class, method and instruction address
#[derive(Debug)]
pub struct DvmClassMethodIdx(shuriken::hdvm_class_method_idx_t);

/// Type alias for Shuriken's `hdvm_method_idx_t`
///
///  Cross-ref that contains a method and instruction address
#[derive(Debug)]
pub struct DvmMethodIdx(shuriken::hdvm_method_idx_t);

/// Type alias for Shuriken's `hdvm_class_field_idx_t`
///
///  Cross-ref that contains class, field and instruction address
#[derive(Debug)]
pub struct DvmClassFieldIdx(shuriken::hdvm_class_field_idx_t);

/// Type alias for Shuriken's `hdvm_class_idx_t`
///
/// Cross-ref that contains class and instruction address
#[derive(Debug)]
pub struct DvmClassIdx(shuriken::hdvm_class_idx_t);

/// Type alias for Shuriken's `hdvm_reftype_method_idx_t`
///
/// Structure that contains a type of reference, a method analysis where reference is and the index
/// in the method where the reference to a class is
#[derive(Debug)]
pub struct DvmRefTypeMethodIdx(shuriken::hdvm_reftype_method_idx_t);

/// Type alias for Shuriken's `hdvm_classxref_t`
///
/// Class cross-ref
#[derive(Debug)]
pub struct DvmClassXRef(shuriken::hdvm_classxref_t);

/// Type alias for Shuriken's `hdvmbasicblock_t`
///
/// Structure that stores information of a basic block
#[derive(Debug)]
pub struct DvmBasicBlock(shuriken::hdvmbasicblock_t);

/// Type alias for Shuriken's `basic_blocks_t`
///
/// Structure to keep all the basic blocks
#[derive(Debug)]
pub struct BasicBlocks(shuriken::basic_blocks_t);

/// Type alias for Shuriken's `hdvmfieldanalysis_t`
///
/// Field analysis structure
#[derive(Debug)]
pub struct DvmFieldAnalysis(shuriken::hdvmfieldanalysis_t);

/// Type alias for Shuriken's `hdvmstringanalysis_t`
///
/// Structure to keep information about the string analysis [UNUSED FOR NOW]
#[derive(Debug)]
pub struct DvmStringAnalysis(shuriken::hdvmstringanalysis_t);

/// Type alias for Shuriken's `hdvmmethodanalysis_t`
///
/// Structure to keep information about the method analysis
#[derive(Debug)]
pub struct DvmMethodAnalysis(shuriken::hdvmmethodanalysis_t);

/// Type alias for Shuriken's `hdvmclassanalysis_t`
///
/// Structure to keep information about the class analysis
#[derive(Debug)]
pub struct DvmClassAnalysis(shuriken::hdvmclassanalysis_t);

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
            method_ptrs: HashMap::new()
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
            let dvm_class = DvmClass::from_hdvmclass_t(unsafe { *dvm_class_ptr });
            self.class_ptrs.insert(dvm_class.class_name.clone(), dvm_class_ptr);
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
            let dvm_class = DvmClass::from_hdvmclass_t(unsafe { *class_ptr });
            self.class_ptrs.insert(dvm_class.class_name.clone(), class_ptr);
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
            let dvm_method = unsafe { DvmMethod::from_hdvmmethod_t(*method_ptr) };
            self.method_ptrs.insert(dvm_method.method_name.clone(), method_ptr);
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
    pub fn get_analyzed_class_by_hdvmclass(&self, class: &DvmClass) -> Option<&DvmClassAnalysis> {
        let class_ptr = self.class_ptrs
            .get(&class.class_name)
            .expect("Cannot find raw pointer for class");

        println!("class_ptr {:#?}", *class_ptr);

        let analysis = unsafe {
            shuriken::get_analyzed_class_by_hdvmclass(self.ptr, *class_ptr)
        };

        unsafe {
            println!("analysis {:#?}", *analysis);
        }

        None
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
    mod dex {
        use super::super::*;
        use std::fs;
        use std::path::PathBuf;

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

            assert_eq!(&class.class_name, "DexParserTest");
            assert_eq!(&class.super_class, "java.lang.Object");
            assert_eq!(&class.source_file, "DexParserTest.java");

            assert_eq!(class.access_flags, vec![DvmAccessFlag::ACC_PUBLIC]);
            assert_eq!(class.instance_fields_size, 2);
            assert_eq!(class.static_fields_size, 0);

            let class_descriptor = String::from("LDexParserTest;");
            let access_flags = [DvmAccessFlag::ACC_PUBLIC];

            for (idx, field) in class.instance_fields.iter().enumerate() {
                let access_flags = DvmAccessFlag::parse(
                    fields[idx]["flags"].parse::<u32>().unwrap(),
                    DvmAccessFlagType::Field
                );

                assert_eq!(field.class_name, class_descriptor);
                assert_eq!(field.name, fields[idx]["name"]);
                assert_eq!(field.access_flags, access_flags);

                if fields[idx]["type"].starts_with("L") {
                    assert_eq!(field.field_type, DexTypes::Class);
                    assert_eq!(field.fundamental_value, DexBasicTypes::FundamentalNone);
                    assert_eq!(field.type_value, "Ljava/lang/String;");
                } else {
                    assert_eq!(field.field_type, DexTypes::Fundamental);
                    assert_eq!(field.fundamental_value, DexBasicTypes::Int);
                    assert_eq!(field.type_value, "I");
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

            assert_eq!(&class.class_name, "DexParserTest");
            assert_eq!(&class.super_class, "java.lang.Object");
            assert_eq!(&class.source_file, "DexParserTest.java");

            assert_eq!(class.access_flags, vec![DvmAccessFlag::ACC_PUBLIC]);
            assert_eq!(class.direct_methods_size, 4);
            assert_eq!(class.virtual_methods_size, 0);

            let class_descriptor = String::from("LDexParserTest;");
            let access_flags = [DvmAccessFlag::ACC_PUBLIC];

            for (idx, method) in class.direct_methods.iter().enumerate() {
                let access_flags = DvmAccessFlag::parse(
                    methods[idx]["flags"].parse::<u32>().unwrap(),
                    DvmAccessFlagType::Method
                );

                assert_eq!(method.class_name, class_descriptor);
                assert_eq!(method.dalvik_name, methods[idx]["dalvik_name"]);
                assert_eq!(method.access_flags, access_flags);
            }
        }

        #[test]
        fn test_get_class_by_name() {
            let mut context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));
            let class = context.get_class_by_name("DexParserTest");

            assert!(class.is_some());
            assert_eq!(class.as_ref().unwrap().class_name, "DexParserTest");
            assert_eq!(class.as_ref().unwrap().super_class, "java.lang.Object");
            assert_eq!(class.as_ref().unwrap().source_file, "DexParserTest.java");
            assert_eq!(class.as_ref().unwrap().access_flags, vec![DvmAccessFlag::ACC_PUBLIC]);
        }

        #[test]
        fn test_get_method_by_name() {
            let mut context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));
            let method = context.get_method_by_name("LDexParserTest;->printMessage()V");

            assert!(method.is_some());
            assert_eq!(method.as_ref().unwrap().method_name, "printMessage");
            assert_eq!(method.as_ref().unwrap().class_name, "LDexParserTest;");
            assert_eq!(method.as_ref().unwrap().prototype, "()V");
            assert_eq!(method.as_ref().unwrap().access_flags, vec![DvmAccessFlag::ACC_PRIVATE]);
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
                assert_eq!(dvm_method.method_string
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
        fn test_get_analyzed_class_by_hdvmclass() {
            println!("1");
            let mut context = DexContext::parse_dex(&PathBuf::from("test_files/DexParserTest.dex"));
            context.disassemble_dex();
            let class = context.get_class_by_id(0);
            assert!(class.is_some());
            println!("{class:#?}");
            println!("{context:#?}");

            println!("2");
            context.create_dex_analysis(false);
            println!("3");
            context.analyze_classes();
            println!("4");

            // Check that we get nothing if we have not run `DexContext::disassemble_dex()`
            let dvm_method = context.get_analyzed_class_by_hdvmclass(&class.unwrap());
            println!("{dvm_method:#?}");

            assert!(false);
        }
    }
}
