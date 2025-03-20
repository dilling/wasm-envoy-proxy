// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::time::Duration;
use jwt_simple::{claims::NoCustomClaims, prelude::{RS256PublicKey, RSAPublicKeyLike}};
use log;
use serde::Deserialize;
use serde_json::from_slice;
use std::error::Error;

use proxy_wasm::{
    traits::{Context, HttpContext, RootContext}, types::{Action, ContextType, LogLevel}
};
use base64::prelude::*;


const PUBLIC_KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(3);
const PUBLIC_KEY_CACHE_KEY: &str = "public_key";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(RootHandler) });
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

struct RootHandler;

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

        let n = BASE64_URL_SAFE_NO_PAD.decode(pubkey_comps.n.as_bytes()).unwrap();
        let e = BASE64_URL_SAFE_NO_PAD.decode(pubkey_comps.e.as_bytes()).unwrap();
    
        let key = RS256PublicKey::from_components(&n, &e).unwrap();


        let data = key.to_der().unwrap();
        self.set_shared_data(PUBLIC_KEY_CACHE_KEY, Some(&data), None).unwrap();
    }
}

impl RootContext for RootHandler {
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HttpHandler {}))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        self.set_tick_period(PUBLIC_KEY_REFRESH_INTERVAL);
        // log::info!("on_configure");
        true
    }

    fn on_tick(&mut self) {
        match self.get_shared_data(PUBLIC_KEY_CACHE_KEY) {
            (Some(_), _) => {
                // log::info!("Public Key cached, skipping fetch");
                return;
            },
            (None, _) => log::info!("fetching public key"),
        }

        let _ = self.dispatch_http_call(
            "auth",
            vec![
                (":method", "GET"),
                (":path", "/.well-known/jwks.json"),
                (":authority", "auth"),
            ], 
            None,
            vec![],
            Duration::from_secs(1)
        ).inspect_err( |e| {
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

struct HttpHandler;

impl HttpHandler {
    fn verify_auth(&self) -> Result<(), Box<dyn Error>> {
        let auth_header = self.get_http_request_header("Authorization").ok_or("Missing Authorization Header")?;
        let token = auth_header.split_whitespace().last().ok_or("Invalid Auth Header")?;

        let data = self.get_shared_data(PUBLIC_KEY_CACHE_KEY).0.ok_or("Public key not found in cache")?;
        let public_key = RS256PublicKey::from_der(&data)?;
        public_key.verify_token::<NoCustomClaims>(token, None)?;

        Ok(())
    }
    
}

impl Context for HttpHandler {}

impl HttpContext for HttpHandler {
    fn on_http_request_headers(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        // log::info!("on_http_request_headers");

        match self.verify_auth() {
            Ok(_) => Action::Continue,
            Err(e) => {
                log::error!("Failed to verify token: {:?}", e);

                self.send_http_response(
                    401,
                    vec![("Powered-By", "proxy-wasm")],
                    Some(b"Access forbidden.\n"),
                );

                Action::Continue
            }
        }
    }
}
