//! Parser data structs

use std::ffi::CStr;
use std::slice::from_raw_parts;

use crate::shuriken;
use crate::dvm_access_flags::{ DvmAccessFlag, DvmAccessFlagType };

/// Type alias for Shuriken's `htype_e`
///
/// DEX types of the DVM we have by default fundamental, classes and array
#[derive(Debug, Clone, Copy, PartialEq)]
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
#[derive(Debug, Clone, Copy, PartialEq)]
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
    FundamentalNone = 99
}

/// Type alias for Shuriken's `dexheader_t`
///
/// Structure which contains the information from the header of a DEX file
#[derive(Debug)]
pub struct DvmHeader {
    /// Magic bytes from dex, different values are possible
    magic: [u8; 8],
    /// Checksum to see if file is correct
    checksum: u32,
    /// Signature of dex
    signature: [u8; 20],
    /// Current file size
    file_size: u32,
    /// Size of this header
    header_size: u32,
    /// Type of endianess of the file
    endian_tag: u32,
    /// Size of the link section, or 0 if this file isn't statically linked
    link_size: u32,
    /// Offset from the start of the file to the link section
    link_off: u32,
    /// Offset from the start of the file to the map item
    map_off: u32,
    /// Number of DexStrings
    string_ids_size: u32,
    /// Offset of the DexStrings
    string_ids_off: u32,
    /// Number of DexTypes
    type_ids_size: u32,
    /// Offset of the DexTypes
    type_ids_off: u32,
    /// Number of prototypes
    proto_ids_size: u32,
    /// Offset of the prototypes
    proto_ids_off: u32,
    /// Number of fields
    field_ids_size: u32,
    /// Offset of the fields
    field_ids_off: u32,
    /// Number of methods
    method_ids_size: u32,
    /// Offset of the methods
    method_ids_off: u32,
    /// Number of class definitions
    class_defs_size: u32,
    /// Offset of the class definitions
    class_defs_off: u32,
    /// Data area, containing all the support data for the tables listed above
    data_size: u32,
    /// Data offset
    data_off: u32,
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
    pub fn from_ptr(ptr: shuriken::hdvmfield_t) -> Self {
        let class_name = unsafe {
            CStr::from_ptr(ptr.class_name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let name = unsafe {
            CStr::from_ptr(ptr.name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let type_value = unsafe {
            CStr::from_ptr(ptr.type_value)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let access_flags = DvmAccessFlag::parse(
            ptr.access_flags as u32,
            DvmAccessFlagType::Class
        );

        let field_type = match ptr.type_ {
            0 => DexTypes::Fundamental,
            1 => DexTypes::Class,
            2 => DexTypes::Array,
            _ => DexTypes::Unknown,
        };

        let fundamental_value = if field_type == DexTypes::Fundamental {
            match ptr.fundamental_value {
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

    /// Return a reference to the class name
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Return a reference to the field name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return a reference to the field type
    pub fn field_type(&self) -> DexTypes {
        self.field_type
    }

    /// Return a reference to the fundamental value
    pub fn fundamental_value(&self) -> DexBasicTypes {
        self.fundamental_value
    }

    /// Return a reference to the field type value
    pub fn type_value(&self) -> &str {
        &self.type_value
    }

    /// Return a reference to the access flags
    pub fn access_flags(&self) -> &[DvmAccessFlag] {
        &self.access_flags
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
    pub fn from_ptr(method: shuriken::hdvmmethod_t) -> Self {
        let class_name = unsafe {
            CStr::from_ptr(method.class_name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let method_name = unsafe {
            CStr::from_ptr(method.method_name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let prototype = unsafe {
            CStr::from_ptr(method.prototype)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let access_flags = DvmAccessFlag::parse(method.access_flags.into(), DvmAccessFlagType::Method);

        let dalvik_name = unsafe {
            CStr::from_ptr(method.dalvik_name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let demangled_name = unsafe {
            CStr::from_ptr(method.demangled_name)
                .to_str()
                .expect("Error: string is not valid UTF-8")
                .to_string()
        };

        let code = unsafe {
            from_raw_parts(method.code, method.code_size as usize)
                .to_vec()
        };

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

    /// Return a reference to the class name
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Return a reference to the method name
    pub fn method_name(&self) -> &str {
        &self.method_name
    }

    /// Return a reference to the method prototype
    pub fn prototype(&self) -> &str {
        &self.prototype
    }

    /// Return a reference to the method access flags
    pub fn access_flags(&self) -> &[DvmAccessFlag] {
        &self.access_flags
    }

    /// Return the method's code size
    pub fn code_size(&self) -> usize {
        self.code_size
    }

    /// Return the method's code
    pub fn code(&self) -> &[u8] {
        &self.code
    }

    /// Return a reference to the dalvik name
    pub fn dalvik_name(&self) -> &str {
        &self.dalvik_name
    }

    /// Return a reference to the method demangled name
    pub fn demangled_name(&self) -> &str {
        &self.demangled_name
    }
}


/// Type alias for Shuriken's `hdvmclass_t`
///
/// Structure representing the classes in the DEX file
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
    pub fn from_ptr(ptr: shuriken::hdvmclass_t) -> Self {
        let class_name = unsafe {
            CStr::from_ptr(ptr.class_name)
                 .to_str()
                 .expect("Error: string is not valid UTF-8")
                 .to_string()
        };

        let super_class = unsafe {
            CStr::from_ptr(ptr.super_class)
                 .to_str()
                 .expect("Error: string is not valid UTF-8")
                 .to_string()
        };

        let source_file = unsafe {
            CStr::from_ptr(ptr.source_file)
                 .to_str()
                 .expect("Error: string is not valid UTF-8")
                 .to_string()
        };

        let access_flags = DvmAccessFlag::parse(
            ptr.access_flags as u32,
            DvmAccessFlagType::Class
        );

        let direct_methods = unsafe {
            from_raw_parts(
                ptr.direct_methods,
                ptr.direct_methods_size.into()
            )
                .iter()
                .map(|method| DvmMethod::from_ptr(*method))
                .collect::<Vec<DvmMethod>>()
        };

        let virtual_methods = unsafe {
            from_raw_parts(
                ptr.virtual_methods,
                ptr.virtual_methods_size.into()
            )
                .iter()
                .map(|method| DvmMethod::from_ptr(*method))
                .collect::<Vec<DvmMethod>>()
        };

        let instance_fields =  unsafe {
            from_raw_parts(
                ptr.instance_fields,
                ptr.instance_fields_size.into()
            )
                .iter()
                .map(|field| DvmField::from_ptr(*field))
                .collect::<Vec<DvmField>>()
        };

        let static_fields =  unsafe {
            from_raw_parts(
                ptr.static_fields,
                ptr.static_fields_size.into()
            )
                .iter()
                .map(|field| DvmField::from_ptr(*field))
                .collect::<Vec<DvmField>>()
        };

        DvmClass {
            class_name,
            super_class,
            source_file,
            access_flags,
            direct_methods_size: ptr.direct_methods_size as usize,
            direct_methods,
            virtual_methods_size: ptr.virtual_methods_size as usize,
            virtual_methods,
            instance_fields_size: ptr.instance_fields_size as usize,
            instance_fields,
            static_fields_size: ptr.static_fields_size as usize,
            static_fields
        }
    }

    /// Returns a reference to the class name
    pub fn class_name(&self) -> &str {
        self.class_name.as_str()
    }

    /// Returns a reference to the super class
    pub fn super_class(&self) -> &str {
        &self.super_class
    }

    /// Returns a reference to the source file
    pub fn source_file(&self) -> &str {
        &self.source_file
    }

    /// Returns a reference to the access flags
    pub fn access_flags(&self) -> &[DvmAccessFlag] {
        &self.access_flags
    }

    /// Returns a reference to the direct methods size
    pub fn direct_methods_size(&self) -> usize {
        self.direct_methods_size
    }

    /// Returns a reference to the direct methods
    pub fn direct_methods(&self) -> &[DvmMethod] {
        &self.direct_methods
    }

    /// Returns a reference to the virtual methods size
    pub fn virtual_methods_size(&self) -> usize {
        self.virtual_methods_size
    }

    /// Returns a reference to the virtual methods
    pub fn virtual_methods(&self) -> &[DvmMethod] {
        &self.virtual_methods
    }

    /// Returns a reference to the instance fields size
    pub fn instance_fields_size(&self) -> usize {
        self.instance_fields_size
    }

    /// Returns a reference to the instance fields
    pub fn instance_fields(&self) -> &[DvmField] {
        &self.instance_fields
    }

    /// Returns a reference to the static fields size
    pub fn static_fields_size(&self) -> usize {
        self.static_fields_size
    }

    /// Returns a reference to the static fields
    pub fn static_fields(&self) -> &[DvmField] {
        &self.static_fields
    }
}
