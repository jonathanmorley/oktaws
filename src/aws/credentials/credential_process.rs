use rusoto_sts::Credentials;
use serde::{Serialize, Serializer};

#[derive(Debug)]
pub enum CredentialProcessCredentials {
    V1 {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        expiration: String,
    },
}

impl Serialize for CredentialProcessCredentials {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(untagged)]
        enum CredentialProcessCredentials_<'a> {
            #[serde(rename_all = "PascalCase")]
            V1 {
                access_key_id: &'a str,
                secret_access_key: &'a str,
                session_token: &'a str,
                expiration: &'a str,
            },
        }

        #[derive(Serialize)]
        #[serde(rename_all = "PascalCase")]
        struct VersionedCredentials<'a> {
            version: u64,
            #[serde(flatten)]
            credentials: CredentialProcessCredentials_<'a>,
        }

        let creds = match self {
            CredentialProcessCredentials::V1 {
                access_key_id,
                secret_access_key,
                session_token,
                expiration,
            } => VersionedCredentials {
                version: 1,
                credentials: CredentialProcessCredentials_::V1 {
                    access_key_id,
                    secret_access_key,
                    session_token,
                    expiration,
                },
            },
        };

        creds.serialize(serializer)
    }
}

impl From<Credentials> for CredentialProcessCredentials {
    fn from(creds: Credentials) -> Self {
        Self::V1 {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            expiration: creds.expiration,
        }
    }
}
