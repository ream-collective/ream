use std::{any::type_name, fmt::Debug, marker::PhantomData};

use redb::{Key, TypeName, Value};
use ssz::{Decode, Encode};

/// Wrapper type to handle keys and values using SSZ encoding
#[derive(Debug)]
pub struct SSZEncoding<T>(pub T);

impl<T> Key for SSZEncoding<T>
where
    T: Debug + Encode + Decode + Ord,
{
    fn compare(data1: &[u8], data2: &[u8]) -> std::cmp::Ordering {
        Self::from_bytes(data1).cmp(&Self::from_bytes(data2))
    }
}

impl<T> Value for SSZEncoding<T>
where
    T: Debug + Encode + Decode,
{
    type SelfType<'a>
        = T
    where
        Self: 'a;

    type AsBytes<'a>
        = Vec<u8>
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        let decode = snap::raw::Decoder::new()
            .decompress_vec(data)
            .expect("Failed to decode");

        T::from_ssz_bytes(&decode).expect("Failed to decode SSZ bytes, data corruption?")
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        snap::raw::Encoder::new()
            .compress_vec(&value.as_ssz_bytes())
            .expect("Failed to encode")
    }

    fn type_name() -> TypeName {
        TypeName::new(&format!("SSZEncoding<{}>", type_name::<T>()))
    }
}

/// A value already in [`SSZEncoding`]'s stored form. Opening a table with this value type writes
/// bytes encoded before the write transaction began, so a large value does not hold the write lock
/// while it is encoded and compressed.
#[derive(Debug)]
pub struct SSZEncoded<T>(PhantomData<T>);

impl<T: Encode> SSZEncoded<T> {
    pub fn encode(value: &T) -> Vec<u8> {
        snap::raw::Encoder::new()
            .compress_vec(&value.as_ssz_bytes())
            .expect("Failed to encode")
    }
}

impl<T> Value for SSZEncoded<T>
where
    T: Debug + Encode + Decode,
{
    type SelfType<'a>
        = &'a [u8]
    where
        Self: 'a;

    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        data
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        value
    }

    /// The same name as [`SSZEncoding`], which redb checks when a table is opened.
    fn type_name() -> TypeName {
        SSZEncoding::<T>::type_name()
    }
}
