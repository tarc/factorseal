//! Registry writes, behind a trait so tests can run anywhere and, on
//! Windows, under a test key instead of the real ones.
//!
//! Keys are written as the manifest writes them, `HKCU\…`; the manifest's
//! rules already confined them to the allowed prefixes. A [`Root`] maps
//! them: the user's own `HKCU`, or a test key under it.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Where `HKCU\…` keys go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Root {
    /// The user's own keys.
    CurrentUser,
    /// Under this `HKCU\…` key, for tests: `HKCU\Software\X` becomes
    /// `<key>\Software\X`.
    Test(String),
}

impl Root {
    /// `key` (`HKCU\…`) as a path under `HKEY_CURRENT_USER`.
    pub fn path(&self, key: &str) -> std::io::Result<String> {
        let relative = under_current_user(key)?;
        Ok(match self {
            Self::CurrentUser => relative.to_owned(),
            Self::Test(root) => format!("{}\\{relative}", under_current_user(root)?),
        })
    }
}

/// The part of `key` after `HKCU\`.
fn under_current_user(key: &str) -> std::io::Result<&str> {
    key.split_once('\\')
        .filter(|(hive, rest)| hive.eq_ignore_ascii_case("HKCU") && !rest.is_empty())
        .map(|(_, rest)| rest)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{key} is not under HKCU"),
            )
        })
}

/// The registry operations the installer uses.
pub trait Registry {
    fn set_string(&self, key: &str, name: &str, value: &str) -> std::io::Result<()>;
    fn set_dword(&self, key: &str, name: &str, value: u32) -> std::io::Result<()>;
    /// A missing value or key is not an error.
    fn delete_value(&self, key: &str, name: &str) -> std::io::Result<()>;
    /// Removes the key and everything under it; a missing key is not an
    /// error.
    fn delete_key(&self, key: &str) -> std::io::Result<()>;
    /// A string value, `None` when absent.
    fn get_string(&self, key: &str, name: &str) -> std::io::Result<Option<String>>;
}

/// The Windows registry, with keys mapped through a [`Root`].
#[cfg(windows)]
pub struct SystemRegistry {
    pub root: Root,
}

/// Whether `result` failed because the key or value doesn't exist.
#[cfg(windows)]
fn missing<T>(result: &windows_registry::Result<T>) -> bool {
    // ERROR_FILE_NOT_FOUND, as an HRESULT.
    matches!(result, Err(error) if error.code().0.cast_unsigned() == 0x8007_0002)
}

#[cfg(windows)]
impl Registry for SystemRegistry {
    fn set_string(&self, key: &str, name: &str, value: &str) -> std::io::Result<()> {
        windows_registry::CURRENT_USER
            .create(self.root.path(key)?)
            .and_then(|key| key.set_string(name, value))
            .map_err(std::io::Error::other)
    }

    fn set_dword(&self, key: &str, name: &str, value: u32) -> std::io::Result<()> {
        windows_registry::CURRENT_USER
            .create(self.root.path(key)?)
            .and_then(|key| key.set_u32(name, value))
            .map_err(std::io::Error::other)
    }

    fn delete_value(&self, key: &str, name: &str) -> std::io::Result<()> {
        let result = windows_registry::CURRENT_USER
            .options()
            .read()
            .write()
            .open(self.root.path(key)?)
            .and_then(|key| key.remove_value(name));
        if missing(&result) {
            return Ok(());
        }
        result.map_err(std::io::Error::other)
    }

    fn delete_key(&self, key: &str) -> std::io::Result<()> {
        let result = windows_registry::CURRENT_USER.remove_tree(self.root.path(key)?);
        if missing(&result) {
            return Ok(());
        }
        result.map_err(std::io::Error::other)
    }

    fn get_string(&self, key: &str, name: &str) -> std::io::Result<Option<String>> {
        let result = windows_registry::CURRENT_USER
            .open(self.root.path(key)?)
            .and_then(|key| key.get_string(name));
        if missing(&result) {
            return Ok(None);
        }
        result.map(Some).map_err(std::io::Error::other)
    }
}

/// A registry in memory, for tests on any platform: keys compared without
/// regard to case, as Windows does.
#[derive(Debug, Default)]
pub struct MemoryRegistry {
    values: Mutex<BTreeMap<(String, String), String>>,
}

impl MemoryRegistry {
    /// Every value, as `(key, name) -> value` with keys lowercased.
    pub fn snapshot(&self) -> BTreeMap<(String, String), String> {
        self.values
            .lock()
            .map(|values| values.clone())
            .unwrap_or_default()
    }

    fn with<T>(&self, apply: impl FnOnce(&mut BTreeMap<(String, String), String>) -> T) -> T {
        let mut values = self
            .values
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        apply(&mut values)
    }
}

impl Registry for MemoryRegistry {
    fn set_string(&self, key: &str, name: &str, value: &str) -> std::io::Result<()> {
        self.with(|values| {
            values.insert(
                (key.to_ascii_lowercase(), name.to_owned()),
                value.to_owned(),
            );
        });
        Ok(())
    }

    fn set_dword(&self, key: &str, name: &str, value: u32) -> std::io::Result<()> {
        self.set_string(key, name, &format!("dword:{value}"))
    }

    fn delete_value(&self, key: &str, name: &str) -> std::io::Result<()> {
        self.with(|values| values.remove(&(key.to_ascii_lowercase(), name.to_owned())));
        Ok(())
    }

    fn delete_key(&self, key: &str) -> std::io::Result<()> {
        let key = key.to_ascii_lowercase();
        let below = format!("{key}\\");
        self.with(|values| {
            values.retain(|(other, _), _| *other != key && !other.starts_with(&below));
        });
        Ok(())
    }

    fn get_string(&self, key: &str, name: &str) -> std::io::Result<Option<String>> {
        Ok(self.with(|values| {
            values
                .get(&(key.to_ascii_lowercase(), name.to_owned()))
                .cloned()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_root_moves_every_key_under_it() {
        let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal";
        assert_eq!(
            Root::CurrentUser.path(key).unwrap(),
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal"
        );
        assert_eq!(
            Root::Test(r"HKCU\Software\FactorSeal-setup-test\1".to_owned())
                .path(key)
                .unwrap(),
            r"Software\FactorSeal-setup-test\1\Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal"
        );
        assert!(Root::CurrentUser.path(r"HKLM\Software\X").is_err());
        assert!(Root::Test(r"HKLM\Test".to_owned()).path(key).is_err());
    }

    #[test]
    fn the_memory_registry_removes_whole_keys_without_regard_to_case() {
        let registry = MemoryRegistry::default();
        registry.set_string(r"HKCU\A\B", "x", "1").unwrap();
        registry.set_string(r"HKCU\A\B\C", "y", "2").unwrap();
        registry.set_string(r"HKCU\A\BC", "z", "3").unwrap();
        assert_eq!(
            registry.get_string(r"hkcu\a\b", "x").unwrap().as_deref(),
            Some("1")
        );
        registry.delete_key(r"HKCU\a\b").unwrap();
        assert_eq!(registry.snapshot().len(), 1);
        assert_eq!(
            registry.get_string(r"HKCU\A\BC", "z").unwrap().as_deref(),
            Some("3")
        );
    }
}
