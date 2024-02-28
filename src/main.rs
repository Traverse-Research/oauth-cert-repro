use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use log::error;
use oauth2::ureq::http_client;
use oauth2::{basic::BasicClient, TokenResponse};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    RevocationUrl, Scope, TokenUrl,
};
use url::Url;


pub struct AccessToken {
    secret: String,
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // prevent accidental leaks
        write!(f, "AccessToken([secret])")
    }
}

impl AccessToken {
    fn new(secret: String) -> Self {
        Self { secret }
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthScope {
    /// Push/pull access to our cloud asset storage
    AssetStorage,
    /// Read/write access to the Android publishing endpoint
    AndroidAppPublisher,
}

impl AuthScope {
    pub const fn oauth_scopes(self) -> &'static [&'static str] {
        match self {
            Self::AssetStorage => [
                "openid",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/devstorage.full_control",
            ]
            .as_slice(),
            // https://developers.google.com/android-publisher/api-ref/rest/v3/internalappsharingartifacts/uploadbundle#authorization-scopes
            Self::AndroidAppPublisher => {
                ["https://www.googleapis.com/auth/androidpublisher"].as_slice()
            }
        }
    }

    pub const fn ci_env_var_name(self) -> &'static str {
        match self {
            Self::AssetStorage => "BREDA_CI_GPC_SERVICE_KEY",
            Self::AndroidAppPublisher => "BREDA_CI_GOOGLE_PLAY_PUBLISH_SERVICE_KEY",
        }
    }
}

// These are only really used to log in to the storage bucket
// in the end the access to the storage bucket is still protected by the
// access rights set up in the cloud; ergo we can put these in version control
// since the only thing you can realistically do with these is logging in.
// The rest is hidden behind access tokens and user controls set up on the
// server end of things.
const BREDA_CLIENT_ID: &str =
    "1020289459785-bopkbjt11fbu9dgjbsaockmhfo00u5g2.apps.googleusercontent.com";
const BREDA_CLIENT_NOT_SO_SECRET: &str = "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";

fn to_auth_scopes(auth_scope: AuthScope) -> impl Iterator<Item = Scope> {
    auth_scope
        .oauth_scopes()
        .iter()
        .map(|&s| Scope::new(s.to_string()))
}

pub struct OAuthWebFlow {
    client: BasicClient,
}

impl Default for OAuthWebFlow {
    fn default() -> Self {
        let client_id = ClientId::new(BREDA_CLIENT_ID.to_string());
        let client_secret = ClientSecret::new(BREDA_CLIENT_NOT_SO_SECRET.to_string());

        let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .expect("Invalid authorization endpoint URL");
        let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
            .expect("Invalid token endpoint URL");

        let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_redirect_uri(
                RedirectUrl::new("http://localhost:8080".to_string())
                    .expect("Invalid redirect URL"),
            )
            .set_revocation_uri(
                RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())
                    .expect("Invalid revocation endpoint URL"),
            );

        Self { client }
    }
}

impl OAuthWebFlow {
    /// <https://www.oauth.com/oauth2-servers/making-authenticated-requests/refreshing-an-access-token/>
    fn refresh_token(
        &self,
        token: oauth2::basic::BasicTokenResponse,
        auth_scopes: impl Iterator<Item = Scope>,
    ) -> Option<oauth2::basic::BasicTokenResponse> {
        if let Some(refresh_token) = token.refresh_token() {
            // exchanging the refresh token can fail -> need to re-login

            let mut new_access_token = self
                .client
                .exchange_refresh_token(refresh_token)
                .add_scopes(auth_scopes)
                .request(http_client)
                .ok()?;

            // if we didn't get a new refresh token we can reuse the old one
            if new_access_token.refresh_token().is_none() {
                new_access_token.set_refresh_token(Some(refresh_token.clone()));
            }

            // manually drop token here so we can consume it in this function
            // there's not really a point in refreshing a token without
            // consuming it: we're returning a new token to be used to the
            // caller of this function.
            drop(token);

            Some(new_access_token)
        } else {
            None
        }
    }

    /// This redirects the user the a SAML login page, starts up a tiny webserver
    /// to then get redirected back to, and exchanges state with the oauth server
    /// just to get back the access token we need later on for proving we can
    /// access the data that we need.
    fn run_block_open_website(
        &self,
        auth_scopes: impl Iterator<Item = Scope>,
    ) -> Option<oauth2::basic::BasicTokenResponse> {
        let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        // Scopes explained here:
        // - https://www.oauth.com/oauth2-servers/scope/
        // - https://developers.google.com/identity/protocols/oauth2/scopes
        let (authorize_url, _csrf_state) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(auth_scopes)
            .set_pkce_challenge(pkce_code_challenge)
            .url();

        log::info!("Opening breda login page...");
        if webbrowser::open(authorize_url.as_str()).is_ok() {
            let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

            if let Some(mut stream) = listener.incoming().flatten().next() {
                // Get the information required from the callback URL
                // this information (authorization code and state) is then
                // exchanged with google for an access token.
                // https://www.oauth.com/oauth2-servers/server-side-apps/authorization-code/

                let (code, _state) = {
                    let mut reader = BufReader::new(&stream);

                    let mut request_line = String::new();
                    reader.read_line(&mut request_line).unwrap();

                    let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                    let mut url = "http://localhost".to_string();
                    url.push_str(redirect_url);

                    let url = Url::parse(&url).unwrap();

                    let has_error = url.query_pairs().any(|(key, _)| key == "error");

                    if has_error {
                        return None;
                    }

                    let code_pair = url.query_pairs().find(|(key, _)| key == "code").unwrap();

                    let (_, value) = code_pair;
                    let code = AuthorizationCode::new(value.into_owned());

                    let state_pair = url.query_pairs().find(|(key, _)| key == "state").unwrap();

                    let (_, value) = state_pair;
                    let state = CsrfToken::new(value.into_owned());

                    (code, state)
                };

                let message =
                    "<html><body>Thanks for logging in, you can close this tab now.</body></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                    message.len(),
                    message
                );
                stream.write_all(response.as_bytes()).unwrap();

                return self
                    .client
                    .exchange_code(code)
                    .set_pkce_verifier(pkce_code_verifier)
                    .request(http_client)
                    .ok();
            }
        }

        None
    }

    fn default_file_path() -> std::path::PathBuf {
        "breda-auth-token.json".into()
    }

    fn store_token(token: &oauth2::basic::BasicTokenResponse) {
        let token_json = serde_json::to_string(&token).unwrap();
        let mut opts = std::fs::OpenOptions::new();
        let mut opts = opts.write(true).create(true).truncate(true);

        #[cfg(target_family = "windows")]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts = opts.custom_flags(0x80000000) // FILE_FLAG_WRITE_THROUGH, write operations go directly to disk
        }

        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts = opts.custom_flags(0x101000); // O_SYNC, write operations go directly to disk
        }

        let mut file = opts.open(Self::default_file_path()).unwrap_or_else(|e| {
            panic!(
                "Failed to open file ({:?}), due to: {:?}",
                Self::default_file_path(),
                e
            )
        });

        file.write_all(token_json.as_bytes())
            .expect("Failed to store OAuth token");
        file.sync_all().expect("Failed to sync OAuth token to disk");
    }

    fn load_token() -> Option<oauth2::basic::BasicTokenResponse> {
        let token_json = std::fs::read_to_string(Self::default_file_path())
            .expect("Failed to load OAuth token file");
        match serde_json::from_str(&token_json) {
            Ok(v) => Some(v),
            Err(e) => {
                error!(
                    "Failed to parse OAuth token, due to: {:?}, need to re-authenticate",
                    e
                );
                None
            }
        }
    }

    pub fn run(&self, requested_auth_scope: AuthScope) -> Option<crate::AccessToken> {
        let requested_scopes = to_auth_scopes(requested_auth_scope);
        // if we have a token stored locally, we just refresh it and return that
        let token = if Self::default_file_path().exists() {
            if let Some(token) = Self::load_token() {
                let original_scopes = token.scopes();
                // A list of the scopes previously stored in our JSON token, together with
                // optionally new scopes required for `requested_auth_scope`.  If one or more of
                // these scopes are not granted, refreshing the token will fail and the user is
                // requested to re-login.
                //
                // At that point we will authenticate with **the union** of all scopes, so that the
                // new token has access to the new scopes without being invalidated for the original
                // scopes.
                let all_scopes = requested_scopes
                    .chain(original_scopes.into_iter().flatten().cloned())
                    // Clone because of a borrow on `token`, which will be moved
                    .collect::<Vec<_>>();

                if let Some(token) = self.refresh_token(token, all_scopes.clone().into_iter()) {
                    Some(token)
                } else {
                    // need to handle the case where the token-refresh fails
                    // and restart the login flow
                    self.run_block_open_website(all_scopes.into_iter())
                }
            } else {
                // failed to parse the token file, this can happen when the OS
                // clears out file out by setting it all to NULL bytes for example.
                self.run_block_open_website(requested_scopes)
            }
        } else {
            self.run_block_open_website(requested_scopes)
        }?;

        Self::store_token(&token);
        Some(crate::AccessToken::new(
            token.access_token().secret().clone(),
        ))
    }
}

fn main() {
    OAuthWebFlow::default().run(AuthScope::AssetStorage).unwrap();
}
