//! A real vault for the CLI's unit tests, protected by a fake key protector
//! instead of a hardware backend.

use std::path::Path;
use std::sync::Arc;

use factorseal::{
    HardwareBackend, KeyProtector, KeyProtectorFactory, UnlockCredentials, UnlockFactorKind,
    UnlockGroup, UnlockPolicy, UnsealLeasePolicy, Vault, VaultPlatform, VaultService,
};
use zeroize::Zeroizing;

pub(crate) struct IntegrationProtector {
    key: u8,
}

impl KeyProtector for IntegrationProtector {
    fn backend(&self) -> HardwareBackend {
        HardwareBackend::AndroidTrustedEnvironment
    }

    fn wrap(&self, plaintext: &[u8]) -> factorseal::VaultResult<Vec<u8>> {
        Ok(plaintext.iter().map(|byte| byte ^ self.key).collect())
    }

    fn unwrap(&self, ciphertext: &[u8]) -> factorseal::VaultResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            ciphertext.iter().map(|byte| byte ^ self.key).collect(),
        ))
    }

    fn delete(&self) -> factorseal::VaultResult<()> {
        Ok(())
    }
}

pub(crate) struct IntegrationProtectorFactory;

impl KeyProtectorFactory for IntegrationProtectorFactory {
    fn create(
        &self,
        root: &Path,
        label: &str,
        biometric: bool,
    ) -> factorseal::VaultResult<Box<dyn KeyProtector>> {
        self.open(root, label, biometric)
    }

    fn open(
        &self,
        _root: &Path,
        label: &str,
        _biometric: bool,
    ) -> factorseal::VaultResult<Box<dyn KeyProtector>> {
        let key = if label.contains("-wrap-") { 0x35 } else { 0x97 };
        Ok(Box::new(IntegrationProtector { key }))
    }
}

/// A new vault in `root`, unsealed with a biometric group, and its service
/// opened at `now`.
pub(crate) fn open_service(root: &Path, now: u64) -> (UnlockGroup, Arc<VaultService>) {
    let unlock_group = UnlockGroup::new([UnlockFactorKind::Biometric]).unwrap();
    let policy = UnlockPolicy::new([unlock_group.clone()]).unwrap();
    let unsealed = Vault::create_with_key_protector_policy(
        root,
        VaultPlatform::Android,
        &policy,
        UnlockCredentials::none(),
        &IntegrationProtectorFactory,
    )
    .unwrap();
    let service =
        Arc::new(VaultService::open(root, unsealed, now, UnsealLeasePolicy::default()).unwrap());
    (unlock_group, service)
}
