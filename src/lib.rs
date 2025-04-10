use jwt_simple::{
    claims::JWTClaims,
    prelude::{RS256PublicKey, RSAPublicKeyLike},
};
use log;
use serde::{Deserialize, Serialize};
use serde_json::from_slice;
use std::error::Error;
use std::time::Duration;

use base64::prelude::*;
use proxy_wasm::{
    traits::{Context, HttpContext, RootContext},
    types::{Action, ContextType, LogLevel},
};

const PUBLIC_KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(3);
const PUBLIC_KEY_CACHE_KEY: &str = "public_key";
const POWERED_BY: &str = "wasm-envoy-proxy";

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(default)]
struct FilterConfig {
    /// Name of the Thrift service for which the filter is being configured.
    service_name: Option<String>,
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(RootHandler::default()) });
}}

#[derive(Debug, Clone, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    // use_: String,
    alg: String,
    n: String,
    e: String,
}

#[derive(Default, Clone)]
struct RootHandler {
    config: FilterConfig,
}

#[derive(Deserialize)]
struct GetScopesResponse {
    scopes: String,
}

#[derive(Serialize, Deserialize)]
struct CustomClaims {
    scopes: Vec<String>,
}

#[derive(Debug)]
enum AuthError {
    Unauthenticated(String),
    Unauthorized(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Unauthenticated(msg) => write!(f, "Unauthenticated: {}", msg),
            AuthError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
        }
    }
}

impl Error for AuthError {}

impl RootHandler {
    fn handle_get_token_res(&mut self, jwks: Vec<u8>) {
        let jwks: Jwks = match from_slice(&jwks) {
            Ok(jwks) => jwks,
            Err(e) => {
                log::error!("Failed to parse JWKS: {:?}", e);
                return;
            }
        };

        let pubkey_comps = match jwks.keys.iter().find(|key| key.alg == "RS256") {
            Some(key) => key,
            None => {
                log::error!("No RS256 key found in JWKS");
                return;
            }
        };

        let n = BASE64_URL_SAFE_NO_PAD
            .decode(pubkey_comps.n.as_bytes())
            .unwrap();
        let e = BASE64_URL_SAFE_NO_PAD
            .decode(pubkey_comps.e.as_bytes())
            .unwrap();

        let key = RS256PublicKey::from_components(&n, &e).unwrap();

        let data = key.to_der().unwrap();
        self.set_shared_data(PUBLIC_KEY_CACHE_KEY, Some(&data), None)
            .unwrap();
    }
}

impl RootContext for RootHandler {
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HttpHandler {
            config: self.config.clone(),
            token_claims: None,
            get_scopes_dispatched: false,
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        // Check for the mandatory filter configuration stanza.
        let configuration: Vec<u8> = match self.get_plugin_configuration() {
            Some(c) => c,
            None => {
                log::warn!("configuration missing");

                return false;
            }
        };

        match serde_json::from_slice::<FilterConfig>(configuration.as_ref()) {
            Ok(config) => {
                log::info!("configuring: {:?}", config);
                self.config = config;
            }
            Err(e) => {
                log::warn!("failed to parse configuration: {:?}", e);
                return false;
            }
        }

        self.set_tick_period(PUBLIC_KEY_REFRESH_INTERVAL);
        // log::info!("on_configure");
        return true;
    }

    fn on_tick(&mut self) {
        match self.get_shared_data(PUBLIC_KEY_CACHE_KEY) {
            (Some(_), _) => {
                // log::info!("Public Key cached, skipping fetch");
                return;
            }
            (None, _) => log::info!("fetching public key"),
        }

        let _ = self
            .dispatch_http_call(
                "auth",
                vec![
                    (":method", "GET"),
                    (":path", "/.well-known/jwks.json"),
                    (":authority", "auth"),
                ],
                None,
                vec![],
                Duration::from_secs(1),
            )
            .inspect_err(|e| {
                log::warn!("dispatch_http_call failed, retrying: {:?}", e);
            });
    }
}

impl Context for RootHandler {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        // log::info!("on_http_call_response");

        // Gather the response body of previously dispatched async HTTP call.
        let body = match self.get_http_call_response_body(0, body_size) {
            Some(body) => body,
            None => {
                log::warn!("header providing service returned empty body");

                return;
            }
        };

        // log::info!("{}", String::from_utf8(body.clone()).unwrap());

        self.handle_get_token_res(body);
    }
}

struct HttpHandler {
    config: FilterConfig,
    token_claims: Option<JWTClaims<CustomClaims>>,
    get_scopes_dispatched: bool,
}

impl HttpHandler {
    fn apply_thrift_auth(&mut self, method_name: String) -> () { 
        match self.dispatch_get_scopes(method_name) {
            Ok(_) => (),
            Err(e) => {
                log::warn!("failed to get scopes: {:?}", e);

                self.send_http_response(
                    401,
                    vec![("Powered-By", POWERED_BY)],
                    Some(b"Access forbidden.\n"),
                );
            }
        }

    }

    fn get_thrift_method_from_body(&self) -> Option<String> {
        let method_length = match self.get_http_request_body(4, 4) {
            Some(bytes) if bytes.len() == 4 => usize::from_be_bytes(bytes.try_into().expect("Expected 4 bytes")),
            _ => return None
        };

        let method_name = match self.get_http_request_body(8, method_length) {
            Some(bytes) if bytes.len() == method_length  => String::from_utf8(bytes).unwrap(),
            _ => return None
        };

        Some(method_name)
    }

    fn dispatch_get_scopes(&mut self, method_name: String) -> Result<(), Box<dyn Error>> {
        let service_name = self
            .config
            .service_name
            .as_ref()
            .ok_or("Service name not found")?;

        self.dispatch_http_call(
            "auth",
            vec![
                (":method", "GET"),
                (":path", &format!("/scopes/{service_name}/{method_name}")),
                (":authority", "auth"),
            ],
            None,
            vec![],
            Duration::from_secs(1),
        )
        .map_err(|status| format!("Failed to dispatch get scopes call: status {:?}", status))?;


        self.get_scopes_dispatched = true;

        Ok(())
    }

    fn handle_get_scopes_res(&self, body: Option<Vec<u8>>) {
        match self.validate_auth(body) {
            Ok(_) => self.resume_http_request(),
            Err(AuthError::Unauthenticated(message)) => {
                log::warn!("Unauthenticated: {:?}", message);

                self.send_http_response(
                    401,
                    vec![("Powered-By", POWERED_BY)],
                    Some(b"Access forbidden.\n"),
                );
            }
            Err(AuthError::Unauthorized(message)) => {
                log::warn!("Unauthorized: {:?}", message);

                self.send_http_response(
                    403,
                    vec![("Powered-By", POWERED_BY)],
                    Some(b"Access forbidden.\n"),
                );
            }
        }
    }

    fn validate_auth(&self, body: Option<Vec<u8>>) -> Result<(), AuthError> {
        let claims = self
            .token_claims
            .as_ref()
            .ok_or(AuthError::Unauthenticated("Missing token claims".to_string()))?;

        let parsed_scope_response = self
            .parse_required_scopes(body)
            .map_err(|e| AuthError::Unauthenticated(e.to_string()))?;

        let required_scopes = parsed_scope_response
            .scopes
            .split_whitespace()
            .map(String::from)
            .collect::<Vec<String>>();

        self.authorize(required_scopes, &claims.custom.scopes)
            .map_err(|e| AuthError::Unauthorized(e.to_string()))?;

        Ok(())
    }

    fn parse_required_scopes(
        &self,
        body: Option<Vec<u8>>,
    ) -> Result<GetScopesResponse, Box<dyn Error>> {
        let body = body.ok_or("Empty body from scopes response")?;
        let response: GetScopesResponse = from_slice(&body)?;
        Ok(response)
    }

    fn authorize(
        &self,
        required_scopes: Vec<String>,
        provided_scopes: &Vec<String>,
    ) -> Result<(), Box<dyn Error>> {
        let missing_scopes: Vec<_> = required_scopes
            .iter()
            .filter(|scope| !provided_scopes.contains(scope))
            .collect();

        if missing_scopes.is_empty() {
            Ok(())
        } else {
            Err(format!("Missing required scopes: {:?}", missing_scopes).into())
        }
    }

    fn authenticate(&self) -> Result<JWTClaims<CustomClaims>, Box<dyn Error>> {
        let auth_header = self
            .get_http_request_header("Authorization")
            .ok_or("Missing Authorization Header")?;

        let token = auth_header
            .split_whitespace()
            .last()
            .ok_or("Invalid Auth Header")?;

        let data = self
            .get_shared_data(PUBLIC_KEY_CACHE_KEY)
            .0
            .ok_or("Public key not found in cache")?;

        let public_key = RS256PublicKey::from_der(&data)?;
        let claims = public_key.verify_token::<CustomClaims>(token, None)?;

        Ok(claims)
    }
}

impl Context for HttpHandler {
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        body_size: usize,
        _num_trailers: usize,
    ) {
        let body = self.get_http_call_response_body(0, body_size);
        self.handle_get_scopes_res(body);
    }
}

impl HttpContext for HttpHandler {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        match self.authenticate() {
            Ok(claims) => self.token_claims = Some(claims),
            Err(e) => {
                log::warn!("Unauthenticated: {:?}", e);

                self.send_http_response(
                    401,
                    vec![("Powered-By", POWERED_BY)],
                    Some(b"Access forbidden.\n"),
                );
            }
        }

        Action::Continue
    }

    fn on_http_request_body(&mut self, _body_size: usize, end_of_stream: bool) -> Action {
        // pause if we've already dispatched a call
        if self.get_scopes_dispatched {
            return Action::Pause;
        }
        if let Some(method_name) = self.get_thrift_method_from_body() {
            self.apply_thrift_auth(method_name);
            return Action::Pause;
        }
        
        if end_of_stream {
            log::info!("Reached end of stream without method name");

            self.send_http_response(
                401,
                vec![("Powered-By", POWERED_BY)],
                Some(b"Access forbidden.\n"),
            );
        };

        Action::Pause
    }
}
