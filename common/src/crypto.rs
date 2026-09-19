pub struct SovereignCrypto;

impl SovereignCrypto {
    const TORSION_BLACKLIST: [&'static [u8; 32]; 3] = [
        &[0x00; 32],
        &[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ],
    ];

    pub fn validate_public_key(pubkey: &[u8; 32]) -> Result<(), &'static str> {
        for torsion_point in &Self::TORSION_BLACKLIST {
            if Self::ct_eq(pubkey, torsion_point) {
                return Err("Security fault: Public key matches a known torsion / degenerate point");
            }
        }

        if (pubkey[31] & 0x80) != 0 {
            return Err("Security fault: Public key exceeds field prime modulus (non-canonical high bit)");
        }

        if Self::is_ge_prime(pubkey) {
            return Err("Security fault: Public key value is greater than or equal to field prime p");
        }

        Ok(())
    }

    #[inline(always)]
    fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
        let mut result = 0u8;
        for i in 0..32 {
            result |= a[i] ^ b[i];
        }
        result == 0
    }

    #[inline(always)]
    fn is_ge_prime(pubkey: &[u8; 32]) -> bool {
        let p: [u8; 32] = [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ];

        let mut borrow = 0u16;
        for i in 0..32 {
            let diff = (pubkey[i] as u16).wrapping_sub(p[i] as u16).wrapping_sub(borrow);
            borrow = (diff >> 8) & 1;
        }
        borrow == 0
    }
}

#[cfg(test)]
mod tests {
    use super::SovereignCrypto;

    #[test]
    fn test_valid_key() {
        let valid_key = [0x12u8; 32];
        assert!(SovereignCrypto::validate_public_key(&valid_key).is_ok());
    }

    #[test]
    fn test_zero_key() {
        let zero_key = [0x00u8; 32];
        assert_eq!(
            SovereignCrypto::validate_public_key(&zero_key),
            Err("Security fault: Public key matches a known torsion / degenerate point")
        );
    }

    #[test]
    fn test_one_prefixed_key() {
        let mut key = [0x00u8; 32];
        key[0] = 0x01;
        assert_eq!(
            SovereignCrypto::validate_public_key(&key),
            Err("Security fault: Public key matches a known torsion / degenerate point")
        );
    }

    #[test]
    fn test_prime_overflow_key() {
        let overflow_key: [u8; 32] = [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ];

        assert_eq!(
            SovereignCrypto::validate_public_key(&overflow_key),
            Err("Security fault: Public key value is greater than or equal to field prime p")
        );
    }
}