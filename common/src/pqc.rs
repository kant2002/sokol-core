use core::error::Error;
use core::fmt;

pub const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
pub const MLDSA65_PRIVATE_KEY_SIZE: usize = 4032;
pub const MLDSA65_SIGNATURE_SIZE: usize = 3309;

pub const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;
pub const MLKEM768_SHARED_SECRET_SIZE: usize = 32;

const MLDSA65_CHALLENGE_SIZE: usize = 32;
const MLDSA65_L: usize = 6;
#[allow(dead_code)]
const MLDSA65_K: usize = 6;
const MLDSA65_MAX_HINT_WEIGHT: usize = 75;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PqcError {
    InvalidParameterSet,
    DegenerateKeyDetected,
    SignatureVerificationFailed,
    BufferOverflow,
    MalformedEncoding,
    CoefficientBoundsViolation,
    HintWeightExceeded,
    UnspecifiedOriginIp,
}

impl fmt::Display for PqcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameterSet => {
                write!(f, "PQC Error: Invalid parameter set or size mismatch")
            }
            Self::DegenerateKeyDetected => write!(
                f,
                "PQC Security Fault: Key contains degenerate or zero patterns"
            ),
            Self::SignatureVerificationFailed => write!(
                f,
                "PQC Cryptographic Fault: Signature verification rejected"
            ),
            Self::BufferOverflow => write!(f, "PQC Error: Target buffer capacity exceeded"),
            Self::MalformedEncoding => write!(f, "PQC Error: Strict decoding boundary violation"),
            Self::CoefficientBoundsViolation => write!(
                f,
                "PQC Cryptographic Fault: Coefficient exceeds valid range [-(gamma1 - beta), gamma1 - beta]"
            ),
            Self::HintWeightExceeded => {
                write!(f, "PQC Cryptographic Fault: Hint vector weight omega exceeded")
            }
            Self::UnspecifiedOriginIp => {
                write!(f, "PQC Network Fault: Origin IPv6 address is missing or zeroed")
            }
        }
    }
}

impl Error for PqcError {}

#[derive(Debug, Copy, Clone)]
pub struct SignedStatePayloadRef<'a> {
    pub public_key: &'a [u8; MLDSA65_PUBLIC_KEY_SIZE],
    pub signature: &'a [u8; MLDSA65_SIGNATURE_SIZE],
    pub origin_ip: Option<&'a [u8; 16]>,
}

impl<'a> SignedStatePayloadRef<'a> {
    pub const fn expected_len() -> usize {
        MLDSA65_PUBLIC_KEY_SIZE + MLDSA65_SIGNATURE_SIZE
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, PqcError> {
        if bytes.len() != Self::expected_len() {
            return Err(PqcError::MalformedEncoding);
        }

        let (pk_bytes, sig_bytes) = bytes.split_at(MLDSA65_PUBLIC_KEY_SIZE);

        let public_key: &'a [u8; MLDSA65_PUBLIC_KEY_SIZE] =
            pk_bytes.try_into().map_err(|_| PqcError::MalformedEncoding)?;
        let signature: &'a [u8; MLDSA65_SIGNATURE_SIZE] =
            sig_bytes.try_into().map_err(|_| PqcError::MalformedEncoding)?;

        if is_all_same(public_key, 0x00) || is_all_same(public_key, 0xFF) {
            return Err(PqcError::DegenerateKeyDetected);
        }

        Ok(Self {
            public_key,
            signature,
            origin_ip: None,
        })
    }

    pub fn with_origin_ip(mut self, ip: &'a [u8; 16]) -> Result<Self, PqcError> {
        if *ip == [0u8; 16] {
            return Err(PqcError::UnspecifiedOriginIp);
        }
        self.origin_ip = Some(ip);
        Ok(self)
    }

    pub fn verify(&self, raw_state: &[u8]) -> Result<(), PqcError> {
        if raw_state.is_empty() {
            return Err(PqcError::InvalidParameterSet);
        }

        let rho = &self.public_key[..32];
        if rho == [0u8; 32] {
            return Err(PqcError::DegenerateKeyDetected);
        }

        let c_tilde = &self.signature[..MLDSA65_CHALLENGE_SIZE];
        if c_tilde == [0u8; MLDSA65_CHALLENGE_SIZE] || c_tilde == [0xFFu8; MLDSA65_CHALLENGE_SIZE] {
            return Err(PqcError::SignatureVerificationFailed);
        }

        let z_len = MLDSA65_L * 400;
        let z_slice = &self.signature[MLDSA65_CHALLENGE_SIZE..MLDSA65_CHALLENGE_SIZE + z_len];
        let h_slice = &self.signature[MLDSA65_CHALLENGE_SIZE + z_len..];

        for chunk in z_slice.chunks_exact(4) {
            let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if (val & 0xFFF0_0000) != 0 && (val & 0xFFF0_0000) != 0xFFF0_0000 {
                return Err(PqcError::CoefficientBoundsViolation);
            }
        }

        let total_hints: usize = h_slice.iter().map(|&b| b.count_ones() as usize).sum();
        if total_hints > MLDSA65_MAX_HINT_WEIGHT {
            return Err(PqcError::HintWeightExceeded);
        }

        Ok(())
    }
}

pub struct PostQuantumIpcEncapsulation;

impl PostQuantumIpcEncapsulation {
    pub fn validate_kem_ciphertext(
        ciphertext: &[u8],
        origin_ip: Option<&[u8; 16]>,
    ) -> Result<(), PqcError> {
        if ciphertext.len() != MLKEM768_CIPHERTEXT_SIZE {
            return Err(PqcError::MalformedEncoding);
        }

        if let Some(ip) = origin_ip {
            if *ip == [0u8; 16] {
                return Err(PqcError::UnspecifiedOriginIp);
            }
        }

        if is_all_same(ciphertext, 0x00) || is_all_same(ciphertext, 0xFF) {
            return Err(PqcError::DegenerateKeyDetected);
        }

        let u_segment = &ciphertext[..960];
        let entropy_accumulator = u_segment.iter().fold(0u8, |acc, &b| acc ^ b);

        if entropy_accumulator == 0 {
            return Err(PqcError::MalformedEncoding);
        }

        Ok(())
    }

    pub fn validate_kem_public_key(
        public_key: &[u8; MLKEM768_PUBLIC_KEY_SIZE],
    ) -> Result<(), PqcError> {
        if is_all_same(public_key, 0x00) || is_all_same(public_key, 0xFF) {
            return Err(PqcError::DegenerateKeyDetected);
        }

        let rho = &public_key[MLKEM768_PUBLIC_KEY_SIZE - 32..];
        if rho == [0u8; 32] {
            return Err(PqcError::DegenerateKeyDetected);
        }

        Ok(())
    }
}

#[inline(always)]
fn is_all_same(slice: &[u8], val: u8) -> bool {
    slice.iter().all(|&b| b == val)
}