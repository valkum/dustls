use rustls::internal::msgs::codec::{Codec, Reader};

// Make a distinct type for u24, even though it's a u32 underneath
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub struct u24(pub u32);

impl u24 {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let [a, b, c, d, e, f]: [u8; 6] = bytes.try_into().ok()?;
        Some(Self(u32::from_be_bytes([0, 0, a, b, c, d, e, f])))
    }
}

impl From<u24> for u32 {
    #[inline]
    fn from(v: u24) -> Self {
        v.0 as Self
    }
}

impl TryInto<u24> for u32 {
    type Error = ();

    fn try_into(self) -> Result<u24, Self::Error> {
        if self > 0xffff_ffff_ffffu32 {
            return Err(());
        } else {
            return Ok(u24(self));
        }
    }
}

impl Codec for u24 {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let be_bytes = u32::to_be_bytes(self.0);
        bytes.extend_from_slice(&be_bytes[2..])
    }

    fn read(r: &mut Reader) -> Option<Self> {
        r.take(6).and_then(Self::decode)
    }
}
