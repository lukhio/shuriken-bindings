#![allow(non_camel_case_types)]

//! Helper functions to manipulate access flags
//!
//! Access flags are stored as an unsigned 32 bits integer and can be used for classes, fields, or
//! methods. In this module we define structs to represent these flags and help methods to parse
//! and print them.
//!
//! # Example
//!
//! ```
//! use shuriken_bindings::dvm_access_flags::{ DvmAccessFlag, DvmAccessFlagType };
//!
//! let flags = DvmAccessFlag::parse(0x0001_0009, DvmAccessFlagType::Method);
//!
//! assert_eq!(flags, vec![DvmAccessFlag::ACC_PUBLIC,
//!                        DvmAccessFlag::ACC_STATIC,
//!                        DvmAccessFlag::ACC_CONSTRUCTOR]);
//! ```

use std::fmt;

/// Representation of the different access flag types: for classes, fields, or methods
#[derive(Debug)]
pub enum DvmAccessFlagType {
    /// Flag for a class
    Class,
    /// Flag for a class field
    Field,
    /// Flag for a method
    Method
}

/// Implementation of the `Display` trait for access flag types
impl fmt::Display for DvmAccessFlagType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DvmAccessFlagType::Class  => { write!(f, "class") },
            DvmAccessFlagType::Field  => { write!(f, "field") },
            DvmAccessFlagType::Method => { write!(f, "method") }
        }
    }
}

/// Type alias for Shuriken's `access_flags_e`
///
/// Representation of the different access flag
/// Bitfields of these flags are used to indicate the accessibility and overall properties of
/// classes and class members.
#[derive(Debug, PartialEq)]
pub enum DvmAccessFlag {
    /// Public: visible everywhere
    ACC_PUBLIC,
    /// Private: only visible to defining class
    ACC_PRIVATE,
    /// Protected: visible to package and subclasses
    ACC_PROTECTED,
    /// Static: meaning depends of where the flag is used
    ///   * for classes: is not constructed with an outer `this` reference
    ///   * for methods: does not take a `this` argument
    ///   * for fields: global to defining class
    ACC_STATIC,
    /// Final: meaning depends of where the flag is used
    ///   * for classes: not subclassable
    ///   * for methods: not overridable
    ///   * for fields: immutable after construction
    ACC_FINAL,
    /// Synchronized (only valid for methods): associated lock automatically
    /// acquired around call to this method.
    /// Note: only valid to set when `ACC_NATIVE` is also set.
    ACC_SYNCHRONIZED,
    /// Volatile (only valid for fields): special access rules to help with
    /// thread safety
    ACC_VOLATILE,
    /// Bridge (only valid for methods): method added automatically by the
    /// compiler as a type-safe bridge
    ACC_BRIDGE,
    /// Transient (only valid for fields): the field must not be saved by
    /// default serialization
    ACC_TRANSIENT,
    /// Varargs (only valid for methods): the last argument to this method
    /// should be treated as a "rest" argument by the compiler
    ACC_VARARGS,
    /// Native (only valid for methods): this method is implemented in
    /// native code
    ACC_NATIVE,
    /// Interface (only valid for classes): multiply-implementable abstract class
    ACC_INTERFACE,
    /// Abstract (only valid for classes and methods):
    ///   * for classes: not directly instantiable
    ///   * for methods: unimplemented by this class
    ACC_ABSTRACT,
    /// Strict floating-point (only valid for methods): strict rules for
    /// floating-point arithmetic
    ACC_STRICT,
    /// Synthetic: not directly defined in source code
    ACC_SYNTHETIC,
    /// Annotation (only valid for classes): declared as an annotation class
    ACC_ANNOTATION,
    /// Enum (only valid for classes and fields):
    ///   * for classes: declared as an enumerated type
    ///   * for fields: declared as an enumerated value
    ACC_ENUM,
    /// Constructor (only valid for methods): contructor method
    ACC_CONSTRUCTOR,
    /// Declared synchronized (only valid for methods): method declared
    /// as `synchronized`
    ACC_DECLARED_SYNCHRONIZED,
}

impl DvmAccessFlag {
    /// Converts a raw flag (an unsigned 32 bits integer) into a vector for access flags
    pub fn parse(flag: u32, for_type: DvmAccessFlagType) -> Vec<Self> {
        let mut flags = Vec::new();

        if flag & 0x01 != 0 { flags.push(DvmAccessFlag::ACC_PUBLIC); }

        if flag & 0x02 != 0 { flags.push(DvmAccessFlag::ACC_PRIVATE); }

        if flag & 0x04 != 0 { flags.push(DvmAccessFlag::ACC_PROTECTED); }

        if flag & 0x08 != 0 { flags.push(DvmAccessFlag::ACC_STATIC); }

        if flag & 0x10 != 0 { flags.push(DvmAccessFlag::ACC_FINAL); }
        
        if flag & 0x20 != 0 {
            if let DvmAccessFlagType::Method = for_type {
                flags.push(DvmAccessFlag::ACC_SYNCHRONIZED);
            }
        }

        if flag & 0x40 != 0 {
            match for_type {
                DvmAccessFlagType::Class => { },
                DvmAccessFlagType::Field => {
                    flags.push(DvmAccessFlag::ACC_VOLATILE);
                },
                DvmAccessFlagType::Method => {
                    flags.push(DvmAccessFlag::ACC_BRIDGE);
                }
            }
        }

        if flag & 0x80 != 0 {
            match for_type {
                DvmAccessFlagType::Class => { },
                DvmAccessFlagType::Field => {
                    flags.push(DvmAccessFlag::ACC_TRANSIENT);
                },
                DvmAccessFlagType::Method => {
                    flags.push(DvmAccessFlag::ACC_VARARGS);
                }
            }
        }

        if flag & 0x100 != 0 {
            if let DvmAccessFlagType::Method = for_type {
                flags.push(DvmAccessFlag::ACC_NATIVE);
            }
        }

        if flag & 0x200 != 0 {
            if let DvmAccessFlagType::Class = for_type {
                flags.push(DvmAccessFlag::ACC_INTERFACE);
            }
        }

        if flag & 0x400 != 0 {
            match for_type {
                DvmAccessFlagType::Field => { },
                _ => {
                    flags.push(DvmAccessFlag::ACC_ABSTRACT);
                }
            }
        }

        if flag & 0x800 != 0 {
            if let DvmAccessFlagType::Method = for_type {
                flags.push(DvmAccessFlag::ACC_STRICT);
            }
        }

        if flag & 0x1000 != 0 { flags.push(DvmAccessFlag::ACC_SYNTHETIC); }

        if flag & 0x2000 != 0 {
            if let DvmAccessFlagType::Class = for_type {
                flags.push(DvmAccessFlag::ACC_ANNOTATION);
            }
        }

        if flag & 0x4000 != 0 {
            match for_type {
                DvmAccessFlagType::Method => { },
                _ => {
                    flags.push(DvmAccessFlag::ACC_ENUM);
                }
            }
        }

        if flag & 0x10000 != 0 {
            if let DvmAccessFlagType::Method = for_type {
                flags.push(DvmAccessFlag::ACC_CONSTRUCTOR);
            }
        }

        if flag & 0x20000 != 0 {
            if let DvmAccessFlagType::Method = for_type {
                flags.push(DvmAccessFlag::ACC_DECLARED_SYNCHRONIZED);
            }
        }

        flags
    }

    /// Pretty print a vector of access flags
    pub fn vec_to_string(flags: &[DvmAccessFlag]) -> String {
        let mut output = String::new();
        let flags_len = flags.len();

        for (idx, flag) in flags.iter().enumerate() {
            output.push_str(&flag.to_string());
            if idx < flags_len - 1{
                output.push('|');
            }
        }

        output
    }
}

/// Implementation of the `Display` trait for access flags
impl fmt::Display for DvmAccessFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DvmAccessFlag::ACC_PUBLIC => write!(f, "public" ),
            DvmAccessFlag::ACC_PRIVATE => write!(f, "private" ),
            DvmAccessFlag::ACC_PROTECTED => write!(f, "protected" ),
            DvmAccessFlag::ACC_STATIC => write!(f, "static" ),
            DvmAccessFlag::ACC_FINAL => write!(f, "final" ),
            DvmAccessFlag::ACC_SYNCHRONIZED => write!(f, "synchronized" ),
            DvmAccessFlag::ACC_VOLATILE => write!(f, "volatile" ),
            DvmAccessFlag::ACC_BRIDGE => write!(f, "bridge" ),
            DvmAccessFlag::ACC_TRANSIENT => write!(f, "transient" ),
            DvmAccessFlag::ACC_VARARGS => write!(f, "varargs" ),
            DvmAccessFlag::ACC_NATIVE => write!(f, "native" ),
            DvmAccessFlag::ACC_INTERFACE => write!(f, "interface" ),
            DvmAccessFlag::ACC_ABSTRACT => write!(f, "abstract" ),
            DvmAccessFlag::ACC_STRICT => write!(f, "strict" ),
            DvmAccessFlag::ACC_SYNTHETIC => write!(f, "synthetic" ),
            DvmAccessFlag::ACC_ANNOTATION => write!(f, "annotation" ),
            DvmAccessFlag::ACC_ENUM => write!(f, "enum" ),
            DvmAccessFlag::ACC_CONSTRUCTOR => write!(f, "constructor" ),
            DvmAccessFlag::ACC_DECLARED_SYNCHRONIZED => write!(f, "synchronized" ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_flag_type_display() {
        let class_flag = DvmAccessFlagType::Class;
        let field_flag = DvmAccessFlagType::Field;
        let method_flag = DvmAccessFlagType::Method;

        assert_eq!(class_flag.to_string(), "class");
        assert_eq!(field_flag.to_string(), "field");
        assert_eq!(method_flag.to_string(), "method");
    }

    #[test]
    fn test_access_flag_class_parse() {
        // Test with valid flags
        // Testing all at once because there is no semantics at play here
        let flags = DvmAccessFlag::parse(0x3ffff, DvmAccessFlagType::Class);
        assert_eq!(flags, vec![DvmAccessFlag::ACC_PUBLIC,
                               DvmAccessFlag::ACC_PRIVATE,
                               DvmAccessFlag::ACC_PROTECTED,
                               DvmAccessFlag::ACC_STATIC,
                               DvmAccessFlag::ACC_FINAL,
                               DvmAccessFlag::ACC_INTERFACE,
                               DvmAccessFlag::ACC_ABSTRACT,
                               DvmAccessFlag::ACC_SYNTHETIC,
                               DvmAccessFlag::ACC_ANNOTATION,
                               DvmAccessFlag::ACC_ENUM]);
    }

    #[test]
    fn test_access_flag_field_parse() {
        // Test with valid flags
        // Testing all at once because there is no semantics at play here
        let flags = DvmAccessFlag::parse(0x3ffff, DvmAccessFlagType::Field);
        assert_eq!(flags, vec![DvmAccessFlag::ACC_PUBLIC,
                               DvmAccessFlag::ACC_PRIVATE,
                               DvmAccessFlag::ACC_PROTECTED,
                               DvmAccessFlag::ACC_STATIC,
                               DvmAccessFlag::ACC_FINAL,
                               DvmAccessFlag::ACC_VOLATILE,
                               DvmAccessFlag::ACC_TRANSIENT,
                               DvmAccessFlag::ACC_SYNTHETIC,
                               DvmAccessFlag::ACC_ENUM]);
    }

    #[test]
    fn test_access_flag_method_parse() {
        // Test with valid flags
        // Testing all at once because there is no semantics at play here
        let flags = DvmAccessFlag::parse(0x3ffff, DvmAccessFlagType::Method);
        assert_eq!(flags, vec![DvmAccessFlag::ACC_PUBLIC,
                               DvmAccessFlag::ACC_PRIVATE,
                               DvmAccessFlag::ACC_PROTECTED,
                               DvmAccessFlag::ACC_STATIC,
                               DvmAccessFlag::ACC_FINAL,
                               DvmAccessFlag::ACC_SYNCHRONIZED,
                               DvmAccessFlag::ACC_BRIDGE,
                               DvmAccessFlag::ACC_VARARGS,
                               DvmAccessFlag::ACC_NATIVE,
                               DvmAccessFlag::ACC_ABSTRACT,
                               DvmAccessFlag::ACC_STRICT,
                               DvmAccessFlag::ACC_SYNTHETIC,
                               DvmAccessFlag::ACC_CONSTRUCTOR,
                               DvmAccessFlag::ACC_DECLARED_SYNCHRONIZED]);
    }
}
