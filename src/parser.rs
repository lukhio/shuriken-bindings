use std::ffi::CStr;
use std::slice::from_raw_parts;

use crate::shuriken;
use crate::dvm_access_flags::{ DvmAccessFlag, DvmAccessFlagType };

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
    FundamentalNone = 99
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
