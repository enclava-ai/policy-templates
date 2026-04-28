use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    canonical::{ce_v1_bytes, ce_v1_hash},
    descriptor::{hex_pubkey, hex_signature},
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Deployer,
}

impl Role {
    fn as_str(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Deployer => "deployer",
        }
    }

    pub fn can_deploy(&self) -> bool {
        matches!(self, Role::Owner | Role::Admin | Role::Deployer)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Member {
    pub user_id: Uuid,
    #[serde(with = "hex_pubkey")]
    pub pubkey: VerifyingKey,
    pub role: Role,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OrgKeyring {
    pub org_id: Uuid,
    pub version: u64,
    pub members: Vec<Member>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OrgKeyringEnvelope {
    pub keyring: OrgKeyring,
    #[serde(with = "hex_signature")]
    pub signature: Signature,
    #[serde(with = "hex_pubkey")]
    pub signing_pubkey: VerifyingKey,
}

pub fn verify_keyring<'a>(
    envelope: &'a OrgKeyringEnvelope,
    trusted_owner: &VerifyingKey,
) -> Result<&'a OrgKeyring> {
    if envelope.signing_pubkey.to_bytes() != trusted_owner.to_bytes() {
        bail!("org keyring signer does not match bootstrapped owner pubkey");
    }
    let bytes = canonical_keyring_bytes(&envelope.keyring);
    trusted_owner
        .verify(&bytes, &envelope.signature)
        .map_err(|err| anyhow!("org keyring owner signature verification failed: {err}"))?;
    if !envelope.keyring.members.iter().any(|member| {
        member.role == Role::Owner && member.pubkey.to_bytes() == trusted_owner.to_bytes()
    }) {
        bail!("org keyring does not contain the signing owner as an owner member");
    }
    Ok(&envelope.keyring)
}

pub fn find_deployer_pubkey(keyring: &OrgKeyring, pubkey: &VerifyingKey) -> Result<VerifyingKey> {
    keyring
        .members
        .iter()
        .find(|member| member.pubkey.to_bytes() == pubkey.to_bytes() && member.role.can_deploy())
        .map(|member| member.pubkey)
        .ok_or_else(|| anyhow!("descriptor signing pubkey is not an authorized keyring deployer"))
}

pub fn keyring_fingerprint(keyring: &OrgKeyring) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(canonical_keyring_bytes(keyring)).into()
}

pub fn canonical_keyring_bytes(keyring: &OrgKeyring) -> Vec<u8> {
    let members_hash = canonical_members_hash(&keyring.members);
    let version = keyring.version.to_be_bytes();
    let updated = keyring.updated_at.to_rfc3339();
    ce_v1_bytes(&[
        ("purpose", b"enclava-org-keyring-v1"),
        ("org_id", keyring.org_id.as_bytes().as_slice()),
        ("version", &version),
        ("members", &members_hash),
        ("updated_at", updated.as_bytes()),
    ])
}

fn canonical_member_hash(member: &Member) -> [u8; 32] {
    let pubkey = member.pubkey.to_bytes();
    let added = member.added_at.to_rfc3339();
    ce_v1_hash(&[
        ("user_id", member.user_id.as_bytes().as_slice()),
        ("pubkey", &pubkey),
        ("role", member.role.as_str().as_bytes()),
        ("added_at", added.as_bytes()),
    ])
}

fn canonical_members_hash(members: &[Member]) -> [u8; 32] {
    let mut sorted: Vec<&Member> = members.iter().collect();
    sorted.sort_by_key(|member| member.user_id);
    let records: Vec<(String, [u8; 32])> = sorted
        .iter()
        .map(|member| (member.user_id.to_string(), canonical_member_hash(member)))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, value)| (label.as_str(), value.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 1, 12, 0, 0).unwrap()
    }

    pub fn fixed_owner_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    pub fn fixed_deployer_key() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    pub fn fixed_keyring(owner: &SigningKey, deployer: &SigningKey) -> OrgKeyring {
        OrgKeyring {
            org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            version: 1,
            members: vec![
                Member {
                    user_id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
                    pubkey: owner.verifying_key(),
                    role: Role::Owner,
                    added_at: fixed_time(),
                },
                Member {
                    user_id: Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap(),
                    pubkey: deployer.verifying_key(),
                    role: Role::Deployer,
                    added_at: fixed_time(),
                },
            ],
            updated_at: fixed_time(),
        }
    }

    pub fn sign_keyring(owner: &SigningKey, keyring: OrgKeyring) -> OrgKeyringEnvelope {
        let bytes = canonical_keyring_bytes(&keyring);
        OrgKeyringEnvelope {
            keyring,
            signature: owner.sign(&bytes),
            signing_pubkey: owner.verifying_key(),
        }
    }

    #[test]
    fn keyring_signature_round_trips() {
        let owner = fixed_owner_key();
        let deployer = fixed_deployer_key();
        let envelope = sign_keyring(&owner, fixed_keyring(&owner, &deployer));
        verify_keyring(&envelope, &owner.verifying_key()).unwrap();
    }

    #[test]
    fn tampered_keyring_fails() {
        let owner = fixed_owner_key();
        let deployer = fixed_deployer_key();
        let mut envelope = sign_keyring(&owner, fixed_keyring(&owner, &deployer));
        envelope.keyring.version = 2;
        assert!(verify_keyring(&envelope, &owner.verifying_key()).is_err());
    }

    #[test]
    fn wrong_owner_fails_before_member_lookup() {
        let owner = fixed_owner_key();
        let deployer = fixed_deployer_key();
        let wrong = SigningKey::from_bytes(&[0x33; 32]);
        let envelope = sign_keyring(&owner, fixed_keyring(&owner, &deployer));
        let err = verify_keyring(&envelope, &wrong.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("bootstrapped owner"));
    }

    #[test]
    fn member_order_is_canonicalized() {
        let owner = fixed_owner_key();
        let deployer = fixed_deployer_key();
        let keyring = fixed_keyring(&owner, &deployer);
        let mut reversed = keyring.clone();
        reversed.members.reverse();
        assert_eq!(
            canonical_keyring_bytes(&keyring),
            canonical_keyring_bytes(&reversed)
        );
    }
}
