//! SRTP cipher implementations using RustCrypto.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use ctr::cipher::{KeyIvInit, StreamCipher};

use str0m_proto::crypto::CryptoError;
use str0m_proto::crypto::{AeadAes128Gcm, AeadAes128GcmCipher};
use str0m_proto::crypto::{AeadAes256Gcm, AeadAes256GcmCipher, Aes128CmSha1_80Cipher};
use str0m_proto::crypto::{SrtpProvider, SupportedAeadAes128Gcm};
use str0m_proto::crypto::{SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};

// Type alias for AES-128 in CTR mode
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

// ============================================================================
// AES-128-CM-SHA1-80 Cipher
// ============================================================================

struct RustCryptoAes128CmSha1_80Cipher {
    key: [u8; 16],
}

impl std::fmt::Debug for RustCryptoAes128CmSha1_80Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoAes128CmSha1_80Cipher").finish()
    }
}

impl Aes128CmSha1_80Cipher for RustCryptoAes128CmSha1_80Cipher {
    fn encrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        // AES-128 Counter Mode (CTR)
        let mut cipher = Aes128Ctr::new(&self.key.into(), iv.into());

        // Copy input to output
        output[..input.len()].copy_from_slice(input);

        // Apply CTR mode encryption (XOR with keystream)
        cipher.apply_keystream(&mut output[..input.len()]);

        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        // AES-CTR is symmetric (same operation for encrypt and decrypt)
        self.encrypt(iv, input, output)
    }
}

// ============================================================================
// AEAD-AES-128-GCM Cipher
// ============================================================================

struct RustCryptoAeadAes128GcmCipher {
    cipher: Aes128Gcm,
}

impl std::fmt::Debug for RustCryptoAeadAes128GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoAeadAes128GcmCipher").finish()
    }
}

impl AeadAes128GcmCipher for RustCryptoAeadAes128GcmCipher {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadAes128Gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        assert!(
            aad.len() >= 12,
            "Associated data length MUST be at least 12 octets"
        );

        let (payload, tag) = output
            .get_mut(..input.len() + 16)
            .ok_or_else(|| CryptoError::Other("AES-GCM output too short".into()))?
            .split_at_mut(input.len());
        {
            #[cfg(feature = "work-profile")]
            let _work = crate::work_profile::Span::gcm(crate::work_profile::GcmStage::Copy, input.len());
            payload.copy_from_slice(input);
        }
        let auth_tag = {
            #[cfg(feature = "work-profile")]
            let _work = crate::work_profile::Span::gcm(crate::work_profile::GcmStage::Aead, input.len());
            self.cipher
                .encrypt_in_place_detached(Nonce::from_slice(iv), aad, payload)
                .map_err(|e| CryptoError::Other(format!("AES-GCM encrypt failed: {:?}", e)))?
        };
        {
            #[cfg(feature = "work-profile")]
            let _work = crate::work_profile::Span::gcm(crate::work_profile::GcmStage::Copy, auth_tag.len());
            tag.copy_from_slice(&auth_tag);
        }
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; AeadAes128Gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert!(input.len() >= AeadAes128Gcm::TAG_LEN);

        let nonce = Nonce::from_slice(iv);

        // Concatenate AAD slices if needed
        let aad_vec: Vec<u8>;
        let aad = if aads.len() == 1 {
            aads[0]
        } else {
            aad_vec = aads.concat();
            &aad_vec
        };

        let payload_len = input.len() - AeadAes128Gcm::TAG_LEN;
        let payload = output
            .get_mut(..payload_len)
            .ok_or_else(|| CryptoError::Other("AES-GCM output too short".into()))?;
        payload.copy_from_slice(&input[..payload_len]);
        let tag = GenericArray::from_slice(&input[payload_len..]);
        if let Err(error) = self.cipher.decrypt_in_place_detached(nonce, aad, payload, tag) {
            payload.fill(0);
            return Err(CryptoError::Other(format!(
                "AES-GCM decrypt failed: {:?}",
                error
            )));
        }
        Ok(payload_len)
    }
}

// ============================================================================
// AEAD-AES-256-GCM Cipher
// ============================================================================

struct RustCryptoAeadAes256GcmCipher {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for RustCryptoAeadAes256GcmCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoAeadAes256GcmCipher").finish()
    }
}

impl AeadAes256GcmCipher for RustCryptoAeadAes256GcmCipher {
    fn encrypt(
        &mut self,
        iv: &[u8; AeadAes256Gcm::IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        assert!(
            aad.len() >= 12,
            "Associated data length MUST be at least 12 octets"
        );

        let (payload, tag) = output
            .get_mut(..input.len() + 16)
            .ok_or_else(|| CryptoError::Other("AES-GCM output too short".into()))?
            .split_at_mut(input.len());
        payload.copy_from_slice(input);
        let auth_tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(iv), aad, payload)
            .map_err(|e| CryptoError::Other(format!("AES-GCM encrypt failed: {:?}", e)))?;
        tag.copy_from_slice(&auth_tag);
        Ok(())
    }

    fn decrypt(
        &mut self,
        iv: &[u8; AeadAes256Gcm::IV_LEN],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        assert!(input.len() >= AeadAes256Gcm::TAG_LEN);

        let nonce = Nonce::from_slice(iv);

        // Concatenate AAD slices if needed
        let aad_vec: Vec<u8>;
        let aad = if aads.len() == 1 {
            aads[0]
        } else {
            aad_vec = aads.concat();
            &aad_vec
        };

        let payload_len = input.len() - AeadAes256Gcm::TAG_LEN;
        let payload = output
            .get_mut(..payload_len)
            .ok_or_else(|| CryptoError::Other("AES-GCM output too short".into()))?;
        payload.copy_from_slice(&input[..payload_len]);
        let tag = GenericArray::from_slice(&input[payload_len..]);
        if let Err(error) = self.cipher.decrypt_in_place_detached(nonce, aad, payload, tag) {
            payload.fill(0);
            return Err(CryptoError::Other(format!(
                "AES-GCM decrypt failed: {:?}",
                error
            )));
        }
        Ok(payload_len)
    }
}

// ============================================================================
// SRTP Profile Support Implementations
// ============================================================================

struct RustCryptoSupportedAes128CmSha1_80;

impl std::fmt::Debug for RustCryptoSupportedAes128CmSha1_80 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSupportedAes128CmSha1_80")
            .finish()
    }
}

impl SupportedAes128CmSha1_80 for RustCryptoSupportedAes128CmSha1_80 {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        Box::new(RustCryptoAes128CmSha1_80Cipher { key })
    }
}

struct RustCryptoSupportedAeadAes128Gcm;

impl std::fmt::Debug for RustCryptoSupportedAeadAes128Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSupportedAeadAes128Gcm").finish()
    }
}

impl SupportedAeadAes128Gcm for RustCryptoSupportedAeadAes128Gcm {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
        Box::new(RustCryptoAeadAes128GcmCipher { cipher })
    }
}

struct RustCryptoSupportedAeadAes256Gcm;

impl std::fmt::Debug for RustCryptoSupportedAeadAes256Gcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSupportedAeadAes256Gcm").finish()
    }
}

impl SupportedAeadAes256Gcm for RustCryptoSupportedAeadAes256Gcm {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        Box::new(RustCryptoAeadAes256GcmCipher { cipher })
    }
}

// ============================================================================
// SRTP Provider Implementation
// ============================================================================

pub(super) struct RustCryptoSrtpProvider;

impl std::fmt::Debug for RustCryptoSrtpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoSrtpProvider").finish()
    }
}

impl SrtpProvider for RustCryptoSrtpProvider {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &RustCryptoSupportedAes128CmSha1_80
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &RustCryptoSupportedAeadAes128Gcm
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &RustCryptoSupportedAeadAes256Gcm
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        // Use aes crate for ECB mode
        use aes::Aes128;
        use aes::cipher::{BlockEncrypt, KeyInit};

        let cipher = Aes128::new(GenericArray::from_slice(key));

        // Input is 16 bytes, output needs to be 32 bytes (with PKCS7 padding)
        // For a 16-byte input, PKCS7 adds a full block of padding (16 bytes of 0x10)
        assert!(input.len() == 16);
        assert!(output.len() >= 32);

        // First block: encrypt the input
        let mut block1 = *GenericArray::from_slice(&input[0..16]);
        cipher.encrypt_block(&mut block1);
        output[0..16].copy_from_slice(&block1);

        // Second block: PKCS7 padding (16 bytes of 0x10)
        let mut block2 = GenericArray::from([0x10u8; 16]);
        cipher.encrypt_block(&mut block2);
        output[16..32].copy_from_slice(&block2);
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        // Use aes crate for ECB mode
        use aes::Aes256;
        use aes::cipher::{BlockEncrypt, KeyInit};

        let cipher = Aes256::new(GenericArray::from_slice(key));

        // Input is 16 bytes, output needs to be 32 bytes (with PKCS7 padding)
        // For a 16-byte input, PKCS7 adds a full block of padding (16 bytes of 0x10)
        assert!(input.len() == 16);
        assert!(output.len() >= 32);

        // First block: encrypt the input
        let mut block1 = *GenericArray::from_slice(&input[0..16]);
        cipher.encrypt_block(&mut block1);
        output[0..16].copy_from_slice(&block1);

        // Second block: PKCS7 padding (16 bytes of 0x10)
        let mut block2 = GenericArray::from([0x10u8; 16]);
        cipher.encrypt_block(&mut block2);
        output[16..32].copy_from_slice(&block2);
    }
}

#[cfg(test)]
mod in_place_tests {
    use super::*;
    use aes_gcm::aead::{Aead, Payload};

    #[test]
    fn gcm128_matches_reference_and_rejects_tampering() {
        let key = [0x21; 16];
        let iv = [0x36; 12];
        let aad = b"rtp-header-12";
        let plain = vec![0x52; 1201];
        let reference = Aes128Gcm::new(GenericArray::from_slice(&key))
            .encrypt(Nonce::from_slice(&iv), Payload { msg: &plain, aad })
            .unwrap();
        let mut cipher = RustCryptoAeadAes128GcmCipher {
            cipher: Aes128Gcm::new(GenericArray::from_slice(&key)),
        };
        let mut encrypted = vec![0; plain.len() + 16];
        cipher.encrypt(&iv, aad, &plain, &mut encrypted).unwrap();
        assert_eq!(encrypted, reference);
        let mut decoded = vec![0; plain.len()];
        assert_eq!(
            cipher.decrypt(&iv, &[aad], &encrypted, &mut decoded).unwrap(),
            plain.len()
        );
        assert_eq!(decoded, plain);
        encrypted[0] ^= 1;
        assert!(cipher.decrypt(&iv, &[aad], &encrypted, &mut decoded).is_err());
        assert!(decoded.iter().all(|byte| *byte == 0));
        assert!(cipher.encrypt(&iv, aad, &plain, &mut encrypted[..16]).is_err());
    }

    #[cfg(feature = "work-profile")]
    #[test]
    fn profiled_gcm_preserves_bytes_and_classifies_media() {
        use crate::work_profile::{Context, GcmStage, Span, with_media};
        fn tick()->Option<u64> {
            thread_local!{static T:std::cell::Cell<u64>=const{std::cell::Cell::new(0)};}
            Some(T.with(|t|{let v=t.get()+1;t.set(v);v}))
        }
        let key=[0x21;16];let iv=[0x36;12];let aad=b"rtp-header-12";
        let mut cipher=RustCryptoAeadAes128GcmCipher{cipher:Aes128Gcm::new(GenericArray::from_slice(&key))};
        let c=Context::begin(tick);
        for (audio,len) in [(true,80),(false,1201)] {
            let input=vec![0x52;len];let mut output=vec![0;len+16];
            with_media(audio,||{
                let _p=Span::gcm(GcmStage::Provider,len);
                cipher.encrypt(&iv,aad,&input,&mut output).unwrap();
            });
            let expected=Aes128Gcm::new(GenericArray::from_slice(&key)).encrypt(Nonce::from_slice(&iv),Payload{msg:&input,aad}).unwrap();
            assert_eq!(output,expected);
        }
        let ledger=c.finish();assert!(ledger.valid);
        for (base,len) in [(12,80),(18,1201)] {
            assert_eq!(ledger.calls[base+4],1);assert_eq!(ledger.bytes[base+4],len);
            assert_eq!(ledger.calls[base+3],2);assert_eq!(ledger.bytes[base+3],len+16);
            assert!(ledger.cpu[base+4]>0);
        }
        assert_eq!(ledger.calls[2],0);
    }

    #[test]
    fn gcm256_matches_reference_and_rejects_tampering() {
        let key = [0x42; 32];
        let iv = [0x63; 12];
        let aad = b"rtp-header-12";
        let plain = vec![0x53; 1201];
        let reference = Aes256Gcm::new(GenericArray::from_slice(&key))
            .encrypt(Nonce::from_slice(&iv), Payload { msg: &plain, aad })
            .unwrap();
        let mut cipher = RustCryptoAeadAes256GcmCipher {
            cipher: Aes256Gcm::new(GenericArray::from_slice(&key)),
        };
        let mut encrypted = vec![0; plain.len() + 16];
        cipher.encrypt(&iv, aad, &plain, &mut encrypted).unwrap();
        assert_eq!(encrypted, reference);
        let mut decoded = vec![0; plain.len()];
        assert_eq!(
            cipher.decrypt(&iv, &[aad], &encrypted, &mut decoded).unwrap(),
            plain.len()
        );
        assert_eq!(decoded, plain);
        encrypted[0] ^= 1;
        assert!(cipher.decrypt(&iv, &[aad], &encrypted, &mut decoded).is_err());
        assert!(decoded.iter().all(|byte| *byte == 0));
        assert!(cipher.encrypt(&iv, aad, &plain, &mut encrypted[..16]).is_err());
    }
}
