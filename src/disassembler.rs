//! Disassembler data structs

use std::ffi::CStr;
use std::slice::from_raw_parts;

use crate::shuriken;
use crate::parser::DvmMethod;

/// Type alias for Shuriken's `dexinsttype_e`
///
/// Instruction types from the Dalvik Virtual Machine
#[derive(Debug, Clone, Copy, PartialEq)]
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
    DexNoneOp = 99,
}

/// Type alias for Shuriken's `hdvminstruction_t`
///
/// Structure for an instruction in the dalvik virtual machine
#[derive(Debug, PartialEq)]
pub struct DvmInstruction {
    instruction_type: DexInstType,
    instruction_length: usize,
    address: u64,
    // TODO: replace with a enum of all opcodes maybe?
    op: u32,
    disassembly: String
}

impl DvmInstruction {
    pub fn from_ins(ins: shuriken::hdvminstruction_t) -> Self {
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

    /// Return the instruction type
    pub fn instruction_type(&self) -> DexInstType {
        self.instruction_type
    }

    /// Return the instruction length
    pub fn instruction_length(&self) -> usize {
        self.instruction_length
    }

    /// Return the instruction address
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Return the instruction opcode
    pub fn op(&self) -> u32 {
        self.op
    }

    /// Return the instruction string disassembly representation
    pub fn disassembly(&self) -> &str {
        &self.disassembly
    }
}

/// Type alias for Shuriken's `dvmhandler_data_t`
///
/// Structure that keeps information about a handler
#[derive(Debug, PartialEq)]
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

    /// Return the handler type
    pub fn handler_type(&self) -> &str {
        &self.handler_type
    }

    /// Return the handler start address
    pub fn handler_start_addr(&self) -> u64 {
        self.handler_start_addr
    }
}

/// Type alias for Shuriken's `dvmexceptions_data_t`
///
/// Structure with the information from the exceptions in the code
#[derive(Debug, PartialEq)]
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

    /// Return the try value start address
    pub fn try_value_start_addr(&self) -> u64 {
        self.try_value_start_addr
    }

    /// Return the try value end address
    pub fn try_value_end_addr(&self) -> u64 {
        self.try_value_end_addr
    }

    /// Return the number of handlers
    pub fn n_of_handlers(&self) -> usize {
        self.n_of_handlers
    }

    /// Return a reference to the handlers
    pub fn handlers(&self) -> &[DvmHandlerData] {
        &self.handlers
    }
}

/// Type alias for Shuriken's `dvmdisassembled_method_t`
///
/// Structure that represents a disassembled method from the dalvik file
#[derive(Debug, PartialEq)]
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
    pub fn from_dvmdisassembled_method_t(
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

    /// Create from raw pointer
    ///
    /// This is basically a wrapper around [`from_dvmdisassembled_method_t`]
    ///
    /// [`from_dvmdisassembled_method_t`]: struct.DvmDisassembledMethod.html#method.from_dvmdisassembled_method_t
    pub fn from_ptr(ptr: shuriken::dvmdisassembled_method_t) -> Self {
        // Check if we have a non-null pointer to the `DvmMethod` object
        if ptr.method_id.is_null() {
            panic!("DvmMethod pointer is null");
        }

        let dvm_method = unsafe { DvmMethod::from_ptr(*ptr.method_id) };

        DvmDisassembledMethod::from_dvmdisassembled_method_t(ptr, dvm_method)
    }

    /// Return a reference to the method id
    pub fn method_id(&self) -> &DvmMethod {
        &self.method_id
    }

    /// Return the number of registers
    pub fn n_of_registers(&self) -> usize {
        self.n_of_registers
    }

    /// Return the number of exceptions
    pub fn n_of_exceptions(&self) -> usize {
        self.n_of_exceptions
    }

    /// Return a reference to the exception information
    pub fn exception_information(&self) -> &[DvmException] {
        &self.exception_information
    }

    /// Return the number of instructions
    pub fn n_of_instructions(&self) -> usize {
        self.n_of_instructions
    }

    /// Return the method string
    pub fn method_string(&self) -> &str {
        &self.method_string
    }

    /// Return the instructions
    pub fn instructions(&self) -> &[DvmInstruction] {
        &self.instructions
    }
}
