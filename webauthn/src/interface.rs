//! Types that are expected to be serialised in applications using
//! [crate::Webauthn]

use serde::{Deserialize, Serialize};

use webauthn_core::interface::{AuthenticationResult, AuthenticationState, RegistrationState};
use webauthn_core::proto::{COSEAlgorithm, Credential, CredentialID};

/// An in progress registration session for a [Passkey].
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly
/// weaken the security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to
/// achieve this see the [crate#
/// allow-serialising-registration-and-authentication-state] level
/// documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[archive_attr(derive(bytecheck::CheckBytes))]
pub struct PasskeyRegistration {
    pub rs: RegistrationState,
}

/// An in progress authentication session for a [Passkey].
///
/// WARNING ⚠️  YOU MUST STORE THIS VALUE SERVER SIDE.
///
/// Failure to do so *may* open you to replay attacks which can significantly
/// weaken the security of this system.
///
/// In some cases you *may* wish to serialise this value. For details on how to
/// achieve this see the [crate#
/// allow-serialising-registration-and-authentication-state] level
/// documentation.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "danger-allow-state-serialisation",
    derive(Serialize, Deserialize)
)]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[archive_attr(derive(bytecheck::CheckBytes))]
pub struct PasskeyAuthentication {
    pub ast: AuthenticationState,
}

/// A Passkey for a user. A passkey is a term that covers all possible
/// authenticators that may exist. These could be roaming credentials such as
/// Apple's Account back passkeys, they could be a users Yubikey, a Windows
/// Hello TPM, or even a password manager softtoken.
///
/// Passkeys *may* opportunistically have some properties such as
/// discoverability (residence). This is not a guarantee since enforcing
/// residence on devices like yubikeys that have limited storage
/// and no administration of resident keys may break the device.
///
/// These can be safely serialised and deserialised from a database for
/// persistance.
#[derive(
    Debug, Clone, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[archive_attr(derive(bytecheck::CheckBytes))]
pub struct Passkey {
    pub cred: Credential,
}

impl Passkey {
    /// Retrieve a reference to this Pass Key's credential ID.
    pub fn cred_id(&self) -> &CredentialID {
        &self.cred.cred_id
    }

    /// Retrieve the type of cryptographic algorithm used by this key
    pub fn cred_algorithm(&self) -> &COSEAlgorithm {
        &self.cred.cred.type_
    }

    /// Post authentication, update this credentials properties.
    ///
    /// To determine if this is required, you can inspect the result of
    /// `authentication_result.needs_update()`. Counter intuitively, most
    /// passkeys will never need their properties updated! This is because
    /// many passkeys lack an internal device activation counter (due to
    /// their synchronisation), and the backup-state flags are rarely if
    /// ever changed.
    ///
    /// If the credential_id does not match, None is returned.
    /// If the cred id matches and the credential is updated, Some(true) is
    /// returned. If the cred id matches, but the credential is not changed,
    /// Some(false) is returned.
    pub fn update_credential(&mut self, res: &AuthenticationResult) -> Option<bool> {
        if res.cred_id() == self.cred_id() {
            let mut changed = false;
            if res.counter() > self.cred.counter {
                self.cred.counter = res.counter();
                changed = true;
            }

            if res.backup_state() != self.cred.backup_state {
                self.cred.backup_state = res.backup_state();
                changed = true;
            }

            if res.backup_eligible() != self.cred.backup_eligible {
                // MUST be false -> true
                assert!(!self.cred.backup_eligible);
                assert!(res.backup_eligible());
                self.cred.backup_eligible = res.backup_eligible();
                changed = true;
            }

            Some(changed)
        } else {
            None
        }
    }
}

#[cfg(feature = "danger-credential-internals")]
impl From<Passkey> for Credential {
    fn from(pk: Passkey) -> Self {
        pk.cred
    }
}

#[cfg(feature = "danger-credential-internals")]
impl From<Credential> for Passkey {
    /// Convert a generic webauthn credential into a Passkey
    fn from(cred: Credential) -> Self {
        Passkey { cred }
    }
}

impl PartialEq for Passkey {
    fn eq(&self, other: &Self) -> bool {
        self.cred.cred_id == other.cred.cred_id
    }
}
