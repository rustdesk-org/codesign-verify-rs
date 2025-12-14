use super::wintrust_sys::*;
use crate::{Error, Name};

#[repr(C)]
struct CRYPT_PROVIDER_CERT_HDR {
    cbStruct: DWORD,
    pCert: PCCERT_CONTEXT,
}

pub(crate) struct Context {
    data: HANDLE,
    signer_ptr: *const std::ffi::c_void,
    leaf_cert_ptr: PCCERT_CONTEXT,
}

impl Drop for Context {
    fn drop(&mut self) {
        close_state_data(self.data);
    }
}

/// Maximum certificate chain depth to traverse.
const MAX_CHAIN_DEPTH: u32 = 32;

pub(super) fn close_state_data(handle: HANDLE) {
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as _,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: 0,
        u: Default::default(),
        dwStateAction: WTD_STATEACTION_CLOSE,
        hWVTStateData: handle,
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: 0,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE as _,
            &mut guid,
            &mut data as *mut _ as _,
        )
    };
}

impl Context {
    pub fn new(state_data: HANDLE) -> Result<Self, Error> {
        let mut ret = Context {
            data: state_data,
            signer_ptr: std::ptr::null(),
            leaf_cert_ptr: std::ptr::null(),
        };

        unsafe {
            let crypt_prov_data = match WTHelperProvDataFromStateData(state_data) {
                data if data.is_null() => return Err(Error::LeafCertNotFound),
                data => data,
            };

            let crypt_prov_sgnr = match WTHelperGetProvSignerFromChain(crypt_prov_data, 0, 0, 0) {
                sgnr if sgnr.is_null() => return Err(Error::LeafCertNotFound),
                sgnr => sgnr,
            };
            ret.signer_ptr = crypt_prov_sgnr;

            let crypt_prov_cert = match WTHelperGetProvCertFromChain(crypt_prov_sgnr, 0) {
                cert if cert.is_null() => return Err(Error::LeafCertNotFound),
                cert => cert as *const CRYPT_PROVIDER_CERT_HDR,
            };
            ret.leaf_cert_ptr = match crypt_prov_cert.as_ref() {
                None => return Err(Error::LeafCertNotFound),
                Some(cert) => cert.pCert as PCCERT_CONTEXT,
            };
        }

        Ok(ret)
    }

    fn get_oid_name(&self, issuer: bool, oid: &str) -> Option<String> {
        use std::os::windows::ffi::OsStringExt;
        let Ok(key) = std::ffi::CString::new(oid) else {
            return None;
        };
        let flag = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };

        // Determine string size:
        let len = unsafe {
            CertGetNameStringW(
                self.leaf_cert_ptr,
                CERT_NAME_ATTR_TYPE,
                flag,
                key.as_bytes_with_nul().as_ptr() as _,
                std::ptr::null_mut(),
                0,
            )
        };

        if len == 1 {
            return None;
        }

        let mut buf = vec![0; len as usize];

        let len = unsafe {
            CertGetNameStringW(
                self.leaf_cert_ptr,
                CERT_NAME_ATTR_TYPE,
                flag,
                key.as_ptr() as _,
                buf.as_mut_ptr(),
                buf.len() as _,
            )
        };

        std::ffi::OsString::from_wide(&buf[..len as usize - 1])
            .into_string()
            .ok()
    }

    pub fn serial(&self) -> Option<String> {
        let serial_blob = unsafe {
            self.leaf_cert_ptr
                .as_ref()?
                .pCertInfo
                .as_ref()?
                .SerialNumber
        };

        let blob =
            unsafe { std::slice::from_raw_parts(serial_blob.pbData, serial_blob.cbData as usize) };

        // For some reason windows stores the serial number in reverse order
        Some(
            blob.iter()
                .fold(String::new(), |v, s| format!("{:02x}{}", s, v)),
        )
    }

    pub fn subject_name(&self) -> Name {
        Name {
            common_name: self.get_oid_name(false, szOID_COMMON_NAME),
            organization: self.get_oid_name(false, "2.5.4.10"),
            organization_unit: self.get_oid_name(false, "2.5.4.11"),
            country: self.get_oid_name(false, "2.5.4.6"),
        }
    }

    pub fn issuer_name(&self) -> Name {
        Name {
            common_name: self.get_oid_name(true, szOID_COMMON_NAME),
            organization: self.get_oid_name(true, "2.5.4.10"),
            organization_unit: self.get_oid_name(true, "2.5.4.11"),
            country: self.get_oid_name(true, "2.5.4.6"),
        }
    }

    pub fn sha1_thumbprint(&self) -> String {
        let cert_ref = unsafe {
            match self.leaf_cert_ptr.as_ref() {
                Some(cert) => cert,
                None => return String::new(), // or handle the error appropriately
            }
        };
        let cert_data = unsafe {
            std::slice::from_raw_parts(cert_ref.pbCertEncoded, cert_ref.cbCertEncoded as _)
        };

        use sha1::Digest;
        let hash = sha1::Sha1::digest(cert_data);

        hash.as_slice()
            .iter()
            .fold(String::new(), |s, byte| s + &format!("{:02x}", byte))
    }

    pub fn sha256_thumbprint(&self) -> String {
        let cert_ref = unsafe {
            match self.leaf_cert_ptr.as_ref() {
                Some(cert) => cert,
                None => return String::new(), // or handle the error appropriately
            }
        };
        let cert_data = unsafe {
            std::slice::from_raw_parts(cert_ref.pbCertEncoded, cert_ref.cbCertEncoded as _)
        };

        use sha2::Digest;
        let hash = sha2::Sha256::digest(cert_data);

        hash.as_slice()
            .iter()
            .fold(String::new(), |s, byte| s + &format!("{:02x}", byte))
    }

    fn cert_context_at(&self, idx: DWORD) -> Option<PCCERT_CONTEXT> {
        if self.signer_ptr.is_null() {
            return None;
        }

        let crypt_prov_cert = unsafe { WTHelperGetProvCertFromChain(self.signer_ptr, idx) };
        if crypt_prov_cert.is_null() {
            return None;
        }

        let crypt_prov_cert = crypt_prov_cert as *const CRYPT_PROVIDER_CERT_HDR;
        unsafe { crypt_prov_cert.as_ref().map(|c| c.pCert as PCCERT_CONTEXT) }
    }

    pub fn chain_spki_sha256(&self) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0..MAX_CHAIN_DEPTH {
            let Some(cert_ptr) = self.cert_context_at(i) else {
                break;
            };
            let Some(cert_ref) = (unsafe { cert_ptr.as_ref() }) else {
                break;
            };
            let Some(spki_der) = spki_der(cert_ref) else {
                continue;
            };

            use sha2::Digest;
            let hash = sha2::Sha256::digest(&spki_der);
            let hex = hash
                .as_slice()
                .iter()
                .fold(String::new(), |s, byte| s + &format!("{:02x}", byte));
            out.push(hex);
        }
        out
    }
}

fn spki_der(cert: &CERT_CONTEXT) -> Option<Vec<u8>> {
    let cert_info = unsafe { cert.pCertInfo.as_ref()? };
    let spki: CERT_PUBLIC_KEY_INFO = cert_info.SubjectPublicKeyInfo;

    let encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    let mut cb: DWORD = 0;

    let ok = unsafe {
        CryptEncodeObjectEx(
            encoding,
            X509_PUBLIC_KEY_INFO,
            &spki as *const _ as _,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut cb,
        )
    };
    if ok == 0 || cb == 0 {
        return None;
    }

    let mut buf = vec![0u8; cb as usize];
    let ok = unsafe {
        CryptEncodeObjectEx(
            encoding,
            X509_PUBLIC_KEY_INFO,
            &spki as *const _ as _,
            0,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as _,
            &mut cb,
        )
    };
    if ok == 0 || cb == 0 {
        return None;
    }

    buf.truncate(cb as usize);
    Some(buf)
}
