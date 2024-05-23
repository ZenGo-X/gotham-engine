// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use log::info;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Instant;


pub(crate) type Result<T> = std::result::Result<T, failure::Error>;

#[derive(Debug)]
pub struct ClientShim<C: Client> {
    pub client: C,
    pub auth_token: Option<String>,
    pub customer_id: Option<String>,
    pub endpoint: String,
}

impl ClientShim<reqwest::blocking::Client> {
    pub fn new(endpoint: String, auth_token: Option<String>, customer_id: Option<String>,) -> ClientShim<reqwest::blocking::Client> {
        let client = reqwest::blocking::Client::new();
        ClientShim {
            client,
            auth_token,
            customer_id,
            endpoint,
        }
    }
}

impl<C: Client> ClientShim<C> {
    pub fn new_with_client(endpoint: String, auth_token: Option<String>, customer_id: Option<String>, client: C) -> Self {
        Self {
            client,
            auth_token,
            customer_id,
            endpoint,
        }
    }
    pub fn post<V>(&self, path: &str) -> Option<V>
        where
            V: serde::de::DeserializeOwned,
    {
        let start = Instant::now();
        let res = self
            .client
            .post(&self.endpoint, path, self.auth_token.clone(), self.customer_id.clone(), "{}");
        // info!("(req {}, took: {:?})", path, TimeFormat(start.elapsed()));
        res
    }

    pub fn postb<T, V>(&self, path: &str, body: T) -> Option<V>
        where
            T: serde::ser::Serialize,
            V: serde::de::DeserializeOwned,
    {
        let start = Instant::now();
        let res = self
            .client
            .post(&self.endpoint, path, self.auth_token.clone(), self.customer_id.clone(), body);
        // info!("(req {}, took: {:?})", path, TimeFormat(start.elapsed()));
        res
    }
}

pub trait Client: Sized {
    fn post<V: DeserializeOwned, T: Serialize>(
        &self,
        endpoint: &str,
        uri: &str,
        bearer_token: Option<String>,
        customer_id: Option<String>,
        body: T,
    ) -> Option<V>;
}

const X_CUSTOMER_ID_HEADER: &str = "x-customer-id";


impl Client for reqwest::blocking::Client {
    fn post<V: DeserializeOwned, T: Serialize>(
        &self,
        endpoint: &str,
        uri: &str,
        bearer_token: Option<String>,
        customer_id: Option<String>,
        body: T,
    ) -> Option<V> {
        let mut b = self.post(&format!("{}/{}", endpoint, uri));
        if let Some(token) = bearer_token {
            b = b.bearer_auth(token);
        }

        if let Some(customer_id) = customer_id {
            b = b.header(X_CUSTOMER_ID_HEADER, customer_id);
        }

        let value = b.json(&body).send().ok()?.text().ok()?;
        serde_json::from_str(value.as_str()).ok()
    }
}