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
use jwt_simple::prelude::RS256PublicKey;
use log;
use serde::Deserialize;
use serde_json::from_slice;

use proxy_wasm::{
    traits::{Context, HttpContext, RootContext}, types::{Action, ContextType, LogLevel}
};

const PUBLIC_KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(3);

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
    kty: String,
    kid: String,
    // use_: String,
    alg: String,
    n: String,
    e: String,
}

#[derive(Default)]
struct RootHandler {
    public_key: Option<RS256PublicKey>,
}

impl RootHandler {
    fn handle_get_token_res(&mut self, jwks: Vec<u8>) {
        let jwks: Jwks = match from_slice(&jwks) {
            Ok(jwks) => jwks,
            Err(e) => {
                log::error!("Failed to parse JWKS: {:?}", e);
                return;
            }
        };

        let pubkey_comps = match jwks.keys.get(0) {
            Some(key) => key,
            None => {
                log::error!("No keys found in JWKS");
                return;
            }
        };

        log::info!("Public Key: {:?}", pubkey_comps);

        let key = RS256PublicKey::from_components(&pubkey_comps.n.as_bytes(), &pubkey_comps.e.as_bytes()).unwrap();

        self.public_key = Some(key);
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
        log::info!("on_configure");
        true
    }

    fn on_tick(&mut self) {
        match self.public_key {
            Some(_) => {
                log::info!("Public Key cached, skipping fetch");
                return;
            },
            None => log::info!("fetching public key"),
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

        log::info!("on_http_call_response");

        // Gather the response body of previously dispatched async HTTP call.
        let body = match self.get_http_call_response_body(0, body_size) {
            Some(body) => body,
            None => {
                log::warn!("header providing service returned empty body");

                return;
            }
        };

        log::info!("{}", String::from_utf8(body.clone()).unwrap());

        self.handle_get_token_res(body);
        
        // self.set_shared_data(PUBLIC_KEY_CACHE_KEY, Some(body.as_slice()), None);
    }
}

struct HttpHandler;

impl Context for HttpHandler {}

impl HttpContext for HttpHandler {
    // fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
    //     log(LogLevel::Debug, "on_http_request_headers").unwrap();
    //     Action::Continue
    // }

    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        log::info!("on_http_request_headers");

        // let public_key = self.get_shared_data(PUBLIC_KEY_CACHE_KEY)
        // match public_key {
        //     Some(public_key) => {
        //         let public_key = String::from_utf8(public_key).unwrap();
        //         log::debug!("public key: {}", public_key);
        //     }
        //     None => {
        //         log::debug!("public key not found");
        //     }
        // }
        Action::Continue
    }

    fn on_http_request_body(&mut self, _body_size: usize, _end_of_stream: bool) -> Action {
        log::info!("on_http_request_body");
        Action::Continue
    }
}
