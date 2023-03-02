//! # Webauthn-rs - Webauthn for Rust Server Applications
//!
//! Webauthn is a standard allowing communication between servers, browsers and
//! authenticators to allow strong, passwordless, cryptographic authentication
//! to be performed. Webauthn is able to operate with many authenticator types,
//! such as U2F, TouchID, Windows Hello and many more.
//!
//! This library aims to provide a secure Webauthn implementation that you can
//! plug into your application, so that you can provide Webauthn to your users.
//!
//! There are a number of focused use cases that this library provides, which
//! are described in the [WebauthnBuilder] and [Webauthn] struct.
//!
//! # Getting started
//!
//! In the simplest case where you just want to replace passwords with strong
//! self contained multifactor authentication, you should use our passkey flow.
//!
//! ```
//! use webauthn_rs::prelude::*;
//!
//! let rp_id = "example.com";
//! let rp_origin = Url::parse("https://idm.example.com").expect("Invalid URL");
//! let mut builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
//! let webauthn = builder.build().expect("Invalid configuration");
//!
//! // Initiate a basic registration flow to enroll a cryptographic authenticator
//! let (ccr, skr) = webauthn
//!     .start_passkey_registration(Uuid::new_v4(), "claire", "Claire", None)
//!     .expect("Failed to start registration.");
//! ```
//!
//! After this point you then need to use `finish_passkey_registration`,
//! followed by `start_passkey_authentication` and
//! `finish_passkey_authentication`
//!
//! No other authentication factors are needed! A passkey combines inbuilt user
//! verification (pin, biometrics, etc) with a hardware cryptographic
//! authenticator.
//!
//! # Tutorial
//!
//! Tutorials and examples on how to use this library in your website project is on the project github <https://github.com/valeralabs/apiv2/tree/master/tutorial>
//!
//! # Features
//!
//! This library supports some optional features that you may wish to use. These
//! are all disabled by default as they have risks associated that you need to
//! be aware of as an authentication provider.
//!
//! ## Allow Serialising Registration and Authentication State
//!
//! During a webauthn registration or authentication ceremony, a random
//! challenge is produced and provided to the client. The full content of what
//! is needed for the server to validate this challenge is stored in the
//! associated registration or authentication state types. This value
//! *MUST* be persisted on the server. If you store this in a cookie or some
//! other form of client side stored value, the client can replay a previous
//! authentication state and signature without possession of, or interaction
//! with the authenticator, bypassing pretty much all of the security guarantees
//! of webauthn. Because of this risk by default these states are *not* allowed
//! to be serialised which prevents them from accidentally being placed into a
//! cookie.
//!
//! However there are some *safe* cases of serialising these values. This
//! includes serialising to a database, or using a cookie "memory store" where
//! the client side cookie is a key into a server-side map or similar. Any of
//! these prevent the replay attack threat.
//!
//! An alternate but "less good" method to mitigate replay attacks is to
//! associate a very short expiry window to the cookie if you need full client
//! side state, but this may still allow some forms of real time replay attacks
//! to occur. We do not recommend this.
//!
//! Enabling the feature `danger-allow-state-serialisation` allows you to
//! re-enable serialisation of these types, provided you accept and understand
//! the handling risks associated.
//!
//! ## Credential Internals and Type Changes
//!
//! By default the type wrappers around the keys are opaque. However in some
//! cases you may wish to migrate a key between types (security key to passkey,
//! passwordlesskey to passkey) for example. Alternately, you may wish to access
//! the internals of a credential to implement an alternate serialisation or
//! storage mechanism. In these cases you can access the underlying [Credential]
//! type via Into and From by enabling the feature
//! `danger-credential-internals`. The [Credential] type is exposed via the
//! [prelude] when this feature is enabled.
//!
//! However, you should be aware that manipulating the internals of a
//! [Credential] may affect the usage of that [Credential] in certain use cases.
//! You should be careful when enabling this feature that you do not change
//! [Credential] values.
//!
//! ## User-Presence only SecurityKeys
//!
//! By default, SecurityKeys will opportunistically enforce User Verification
//! (Such as a PIN or Biometric). This can cause issues with Firefox which only
//! supports CTAP1. An example of this is if you register a SecurityKey on
//! chromium it will be bound to always perform UserVerification for the life of
//! the SecurityKey precluding it's use on Firefox.
//!
//! Enabling the feature `danger-user-presence-only-security-keys` changes these
//! keys to prevent User Verification if possible. However, newer keys will
//! confusingly force a User Verification on registration, but will then not
//! prompt for this during usage. Some user surveys have shown this to confuse
//! users to why the UV is not requested, and it can lower trust in these tokens
//! when they are elevated to be self-contained MFA as the user believes these
//! UV prompts to be unreliable and not verified correctly. In these cases you
//! MUST communicate to the user that the UV *may* occur on registration and
//! then will not occur again, and that is *by design*.
//!
//! If in doubt, do not enable this feature.

#[macro_use]
extern crate tracing;

mod interface;

use url::Url;
use uuid::Uuid;
use webauthn_core::error::{WebauthnError, WebauthnResult};
use webauthn_core::proto::*;
use webauthn_core::WebauthnCore;

use crate::interface::*;

/// A prelude of types that are used by `Webauthn`
pub mod prelude {
    pub use crate::interface::*;
    pub use crate::{Webauthn, WebauthnBuilder};
    pub use url::Url;
    pub use uuid::Uuid;
    pub use webauthn_core::error::{WebauthnError, WebauthnResult};
    #[cfg(feature = "danger-credential-internals")]
    pub use webauthn_core::proto::Credential;
    pub use webauthn_core::proto::{AttestationCa, AttestationCaList, AuthenticatorAttachment};
    pub use webauthn_core::proto::{
        AttestationMetadata, AuthenticationResult, AuthenticationState, CreationChallengeResponse,
        CredentialID, ParsedAttestation, ParsedAttestationData, PublicKeyCredential,
        RegisterPublicKeyCredential, RequestChallengeResponse,
    };
    pub use webauthn_core::AttestationFormat;
}

/// A constructor for a new [Webauthn] instance. This accepts and configures a
/// number of site-wide properties that apply to all webauthn operations of this
/// service.
#[derive(Debug)]
pub struct WebauthnBuilder<'a> {
    rp_name: Option<&'a str>,
    rp_id: &'a str,
    allowed_origins: Vec<Url>,
    allow_subdomains: bool,
    allow_any_port: bool,
    algorithms: Vec<COSEAlgorithm>,
}

impl<'a> WebauthnBuilder<'a> {
    /// Initiate a new builder. This takes the relying party id and relying
    /// party origin.
    ///
    /// # Safety
    ///
    /// rp_id is what Credentials (Authenticators) bind themself to - rp_id can
    /// NOT be changed without potentially breaking all of your associated
    /// credentials in the future!
    ///
    /// # Examples
    ///
    /// ```
    /// use webauthn_rs::prelude::*;
    ///
    /// let rp_id = "example.com";
    /// let rp_origin = Url::parse("https://idm.example.com").expect("Invalid URL");
    /// let mut builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
    /// ```
    ///
    /// # Errors
    ///
    /// rp_id *must* be an effective domain of rp_origin. This means that if you
    /// are hosting `https://idm.example.com`, rp_id must be `idm.example.com`, `example.com` or `com`.
    ///
    /// ```
    /// use webauthn_rs::prelude::*;
    ///
    /// let rp_id = "example.com";
    /// let rp_origin = Url::parse("https://idm.different.com").expect("Invalid URL");
    /// assert!(WebauthnBuilder::new(rp_id, &rp_origin).is_err());
    /// ```
    pub fn new(rp_id: &'a str, rp_origin: &'a Url) -> WebauthnResult<Self> {
        // Check the rp_name and rp_id.
        let valid = rp_origin
            .domain()
            .map(|effective_domain| {
                // We need to prepend the '.' here to ensure that myexample.com != example.com,
                // rather than just ends with.
                effective_domain.ends_with(&format!(".{rp_id}")) || effective_domain == rp_id
            })
            .unwrap_or(false);

        if valid {
            Ok(WebauthnBuilder {
                rp_name: None,
                rp_id,
                allowed_origins: vec![rp_origin.to_owned()],
                allow_subdomains: false,
                allow_any_port: false,
                algorithms: COSEAlgorithm::secure_algs(),
            })
        } else {
            error!("rp_id is not an effective_domain of rp_origin");
            Err(WebauthnError::Configuration)
        }
    }

    /// Setting this flag to true allows subdomains to be considered valid in
    /// Webauthn operations. An example of this is if you wish for `https://au.idm.example.com` to be a valid domain
    /// for Webauthn when the configuration is `https://idm.example.com`. Generally this occurs
    /// when you have a centralised IDM system, but location specific systems
    /// with DNS based redirection or routing.
    ///
    /// If in doubt, do NOT change this value. Defaults to "false".
    pub fn allow_subdomains(mut self, allow: bool) -> Self {
        self.allow_subdomains = allow;
        self
    }

    /// Setting this flag skips port checks on origin matches
    pub fn allow_any_port(mut self, allow: bool) -> Self {
        self.allow_any_port = allow;
        self
    }

    /// Set an origin to be considered valid in Webauthn operations. A common
    /// example of this is enabling use with iOS or Android native
    /// "webauthn-like" APIs, which return different origins than a web
    /// browser would.
    pub fn append_allowed_origin(mut self, origin: &Url) -> Self {
        self.allowed_origins.push(origin.to_owned());
        self
    }

    /// Set the relying party name. This may be shown to the user. This value
    /// can be changed in the future without affecting credentials that have
    /// already registered.
    ///
    /// If not set, defaults to rp_id.
    pub fn rp_name(mut self, rp_name: &'a str) -> Self {
        self.rp_name = Some(rp_name);
        self
    }

    /// Complete the construction of the [Webauthn] instance. If an invalid
    /// configuration setting is found, an Error may be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use webauthn_rs::prelude::*;
    ///
    /// let rp_id = "example.com";
    /// let rp_origin = Url::parse("https://idm.example.com").expect("Invalid URL");
    /// let mut builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
    /// let webauthn = builder.build().expect("Invalid configuration");
    /// ```
    pub fn build(self) -> WebauthnResult<Webauthn> {
        Ok(Webauthn {
            core: WebauthnCore::new_unsafe_experts_only(
                self.rp_name.unwrap_or(self.rp_id),
                self.rp_id,
                self.allowed_origins,
                None,
                Some(self.allow_subdomains),
                Some(self.allow_any_port),
            ),
            algorithms: self.algorithms,
        })
    }
}

/// An instance of a Webauthn site. This is the main point of interaction for
/// registering and authenticating credentials for users. Depending on your
/// needs, you'll want to allow users to register and authenticate with
/// different kinds of authenticators.
///
/// *I just want to replace passwords with strong cryptographic authentication,
/// and I don't have other requirements*
///
/// --> You should use `start_passkey_registration`
///
///
/// *I want to replace passwords with strong multi-factor cryptographic
/// authentication, limited to a known set of controlled and trusted
/// authenticator types*
///
/// This type requires `preview-features` enabled as the current form of the
/// Attestation CA List may change in the future.
///
/// --> You should use `start_passwordlesskey_registration`
///
///
/// *I want users to have their identites stored on their devices, and for them
/// to authenticate with  strong multi-factor cryptographic authentication
/// limited to a known set of trusted authenticator types*
///
/// This authenticator type consumes resources of the users devices, and may
/// result in failures, so you should only use it in tightly controlled
/// environments where you supply devices to your users.
///
/// --> You should use `start_devicekey_registration` (still in development)
///
///
/// *I want a security token along with an external password to create
/// multi-factor authentication*
///
/// If possible, consider `start_passkey_registration` OR
/// `start_passwordlesskey_registration` instead - it's likely to provide a
/// better user experience than security keys as MFA!
///
/// --> If you really want a security key, you should use
/// `start_securitykey_registration`
#[derive(Debug)]
pub struct Webauthn {
    core: WebauthnCore,
    algorithms: Vec<COSEAlgorithm>,
}

impl Webauthn {
    /// Get the currently configured origins
    pub fn get_allowed_origins(&self) -> &[Url] {
        self.core.get_allowed_origins()
    }

    /// Initiate the registration of a new pass key for a user. A pass key is
    /// any cryptographic authenticator acting as a single factor of
    /// authentication, far stronger than a password or email-reset link.
    ///
    /// Some examples of pass keys include Yubikeys, TouchID, FaceID, Windows
    /// Hello and others.
    ///
    /// The keys *may* exist and 'roam' between multiple devices. For example,
    /// Apple allows Passkeys to sync between devices owned by the same
    /// Apple account. This can affect your risk model related to these
    /// credentials, but generally in all cases passkeys are better than
    /// passwords!
    ///
    /// You *should* NOT pair this authentication with another factor. A passkey
    /// may opportunistically allow and enforce user-verification (MFA), but
    /// this is NOT guaranteed with all authenticator types.
    ///
    /// `user_unique_id` *may* be stored in the authenticator. This may allow
    /// the credential to  identify the user during certain client side work
    /// flows.
    ///
    /// `user_name` and `user_display_name` *may* be stored in the
    /// authenticator. `user_name` is a friendly account name such as
    /// "claire@example.com". `user_display_name` is the persons chosen
    /// way to be identified such as "Claire". Both can change at *any* time on
    /// the client side, and MUST NOT be used as primary keys. They *may
    /// not* be present in authentication, these are only present to allow
    /// client work flows to display human friendly identifiers.
    ///
    /// `exclude_credentials` ensures that a set of credentials may not
    /// participate in this registration. You *should* provide the list of
    /// credentials that are already registered to this user's account
    /// to prevent duplicate credential registrations. These credentials *can*
    /// be from different authenticator classes since we only require the
    /// `CredentialID`
    ///
    /// # Returns
    ///
    /// This function returns a `CreationChallengeResponse` which you must
    /// serialise to json and send to the user agent (e.g. a browser) for it
    /// to conduct the registration. You must persist on the server the
    /// `PasskeyRegistration` which contains the state of this registration
    /// attempt and is paired to the `CreationChallengeResponse`.
    ///
    /// WARNING ⚠️  YOU MUST STORE THE [PasskeyRegistration] VALUE SERVER SIDE.
    ///
    /// Failure to do so *may* open you to replay attacks which can
    /// significantly weaken the security of this system.
    ///
    /// ```
    /// # use webauthn_rs::prelude::*;
    ///
    /// # let rp_id = "example.com";
    /// # let rp_origin = Url::parse("https://idm.example.com")
    /// #     .expect("Invalid URL");
    /// # let mut builder = WebauthnBuilder::new(rp_id, &rp_origin)
    /// #     .expect("Invalid configuration");
    /// # let webauthn = builder.build()
    /// #     .expect("Invalid configuration");
    ///
    /// // you must store this user's unique id with the account. Alternatelly you can
    /// // use an existed UUID source.
    /// let user_unique_id = Uuid::new_v4();
    ///
    /// // Initiate a basic registration flow, allowing any cryptograhpic authenticator to proceed.
    /// let (ccr, skr) = webauthn
    ///     .start_passkey_registration(
    ///         user_unique_id,
    ///         "claire",
    ///         "Claire",
    ///         None, // No other credentials are registered yet.
    ///     )
    ///     .expect("Failed to start registration.");
    /// ```
    pub fn start_passkey_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> WebauthnResult<(CreationChallengeResponse, PasskeyRegistration)> {
        let attestation = AttestationConveyancePreference::None;
        let credential_algorithms = self.algorithms.clone();
        let require_resident_key = false;
        let authenticator_attachment = None;
        let policy = Some(UserVerificationPolicy::Preferred);
        let reject_passkeys = false;

        let extensions = Some(RequestRegistrationExtensions {
            cred_protect: None,
            uvm: Some(true),
            cred_props: Some(true),
            min_pin_length: None,
            hmac_create_secret: None,
        });

        self.core
            .generate_challenge_register_options(
                user_unique_id.as_bytes(),
                user_name,
                user_display_name,
                attestation,
                policy,
                exclude_credentials,
                extensions,
                credential_algorithms,
                require_resident_key,
                authenticator_attachment,
                reject_passkeys,
            )
            .map(|(ccr, rs)| (ccr, PasskeyRegistration { rs }))
    }

    /// Complete the registration of the credential. The user agent (e.g. a
    /// browser) will return the data of `RegisterPublicKeyCredential`,
    /// and the server provides its paired [PasskeyRegistration]. The details of
    /// the Authenticator based on the registration parameters are asserted.
    ///
    /// # Errors
    /// If any part of the registration is incorrect or invalid, an error will
    /// be returned. See [WebauthnError].
    ///
    /// # Returns
    ///
    /// The returned `Passkey` must be associated to the users account, and is
    /// used for future authentications via `start_passkey_authentication`.
    ///
    /// You MUST assert that the registered credential id has not previously
    /// been registered. to any other account.
    pub fn finish_passkey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> WebauthnResult<Passkey> {
        self.core
            .register_credential(reg, &state.rs, None)
            .map(|cred| Passkey { cred })
    }

    /// Given a set of `Passkey`'s, begin an authentication of the user. This
    /// returns a `RequestChallengeResponse`, which should be serialised to
    /// json and sent to the user agent (e.g. a browser). The server must
    /// persist the [PasskeyAuthentication] state as it is paired to the
    /// `RequestChallengeResponse` and required to complete the authentication.
    ///
    /// WARNING ⚠️  YOU MUST STORE THE [PasskeyAuthentication] VALUE SERVER SIDE.
    ///
    /// Failure to do so *may* open you to replay attacks which can
    /// significantly weaken the security of this system.
    pub fn start_passkey_authentication(
        &self,
        creds: &[Passkey],
    ) -> WebauthnResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        let extensions = None;
        let creds = creds.iter().map(|sk| sk.cred.clone()).collect();
        let policy = UserVerificationPolicy::Preferred;
        let allow_backup_eligible_upgrade = true;

        self.core
            .generate_challenge_authenticate_policy(
                creds,
                policy,
                extensions,
                allow_backup_eligible_upgrade,
            )
            .map(|(rcr, ast)| (rcr, PasskeyAuthentication { ast }))
    }

    /// Given the `PublicKeyCredential` returned by the user agent (e.g. a
    /// browser), and the stored [PasskeyAuthentication] complete the
    /// authentication of the user.
    ///
    /// # Errors
    /// If any part of the registration is incorrect or invalid, an error will
    /// be returned. See [WebauthnError].
    ///
    /// # Returns
    /// On success, [AuthenticationResult] is returned which contains some
    /// details of the Authentication process.
    ///
    /// As per <https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion> 21:
    ///
    /// If the Credential Counter is greater than 0 you MUST assert that the
    /// counter is greater than the stored counter. If the counter is equal
    /// or less than this MAY indicate a cloned credential and you SHOULD
    /// invalidate and reject that credential as a result.
    ///
    /// From this [AuthenticationResult] you *should* update the Credential's
    /// Counter value if it is valid per the above check. If you wish
    /// you *may* use the content of the [AuthenticationResult] for extended
    /// validations (such as the presence of the user verification flag).
    pub fn finish_passkey_authentication(
        &self,
        reg: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> WebauthnResult<AuthenticationResult> {
        self.core.authenticate_credential(reg, &state.ast)
    }
}
