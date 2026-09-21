//! Where the passphrase lives between Touch ID prompts.
//!
//! Our own service name, keyed by keygrip. Deliberately not the `GnuPG` service
//! pinentry-mac writes: that one is found by its label, a string built from the key's
//! description, so an item whose service and account are both right is still invisible
//! if the label differs. Keying on the account alone removes that whole class of bug.

use security_framework::os::macos::keychain::SecKeychain;

const SERVICE: &str = "pinentry-dispatch";
const LEGACY_SERVICE: &str = "GnuPG";

pub struct Store(SecKeychain);

impl Store {
    pub fn open() -> Option<Self> {
        SecKeychain::default().ok().map(Store)
    }

    pub fn get(&self, keygrip: &str) -> Option<String> {
        self.read(SERVICE, keygrip)
    }

    pub fn put(&self, keygrip: &str, passphrase: &str) -> bool {
        self.0
            .set_generic_password(SERVICE, keygrip, passphrase.as_bytes())
            .is_ok()
    }

    pub fn forget(&self, keygrip: &str) {
        if let Ok((_, item)) = self.0.find_generic_password(SERVICE, keygrip) {
            item.delete();
        }
    }

    /// Reading pinentry-mac's item asks macOS for permission once, because that item's
    /// access list names pinentry-mac and not us. Copying it across means the question
    /// is asked once ever rather than on every upgrade.
    pub fn adopt_legacy(&self, keygrip: &str) -> Option<String> {
        let inherited = self.read(LEGACY_SERVICE, keygrip)?;
        self.put(keygrip, &inherited);
        Some(inherited)
    }

    pub fn has(&self, keygrip: &str) -> bool {
        self.0.find_generic_password(SERVICE, keygrip).is_ok()
    }

    pub fn has_legacy(&self, keygrip: &str) -> bool {
        self.0.find_generic_password(LEGACY_SERVICE, keygrip).is_ok()
    }

    fn read(&self, service: &str, account: &str) -> Option<String> {
        let (password, _) = self.0.find_generic_password(service, account).ok()?;
        String::from_utf8(password.to_vec()).ok()
    }
}
