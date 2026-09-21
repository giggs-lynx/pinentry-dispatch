//! Where the passphrase lives between Touch ID prompts.
//!
//! Our own service name, keyed by keygrip. Deliberately not the `GnuPG` service
//! pinentry-mac writes: that one is found by its label, a string built from the key's
//! description, so an item whose service and account are both right is still invisible
//! if the label differs. Keying on the account alone removes that whole class of bug.

use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};
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

    /// Finds the item by reference rather than by fetching it, for the same reason as
    /// `exists`: retrieving the password is what raises the authorisation dialog.
    pub fn forget(&self, keygrip: &str) -> bool {
        let Ok(found) = self.search(SERVICE, keygrip, true) else {
            return false;
        };
        found.into_iter().any(|result| match result {
            SearchResult::Ref(Reference::KeychainItem(item)) => {
                item.delete();
                true
            }
            _ => false,
        })
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
        self.exists(SERVICE, keygrip)
    }

    pub fn has_legacy(&self, keygrip: &str) -> bool {
        self.exists(LEGACY_SERVICE, keygrip)
    }

    /// Attributes only. Fetching the password is what makes macOS ask the user to
    /// authorise access, and an existence check that pops a dialog would block a
    /// pinentry that has nobody in front of it.
    fn exists(&self, service: &str, account: &str) -> bool {
        self.search(service, account, false)
            .is_ok_and(|found| !found.is_empty())
    }

    fn search(
        &self,
        service: &str,
        account: &str,
        want_reference: bool,
    ) -> security_framework::base::Result<Vec<SearchResult>> {
        let mut options = ItemSearchOptions::new();
        options
            .class(ItemClass::generic_password())
            .keychains(&[self.0.clone()])
            .service(service)
            .account(account)
            .limit(1);
        if want_reference {
            options.load_refs(true);
        } else {
            options.load_attributes(true);
        }
        options.search()
    }

    fn read(&self, service: &str, account: &str) -> Option<String> {
        let (password, _) = self.0.find_generic_password(service, account).ok()?;
        String::from_utf8(password.to_vec()).ok()
    }
}
