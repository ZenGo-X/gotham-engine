use crate::engine::traits::KeyGen;
use crate::public::public_gotham::{Config, PublicGotham, DB};
use log::info;
use rocket::{self, catch, catchers, routes, Build, Request, Rocket};
use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr;
// use std::sync::Mutex;
use tokio::sync::Mutex;


#[catch(500)]
fn internal_error() -> &'static str {
    "Internal server error"
}

#[catch(400)]
fn bad_request() -> &'static str {
    "Bad request"
}

#[catch(404)]
fn not_found(req: &Request) -> String {
    format!("Unknown route '{}'.", req.uri())
}

pub fn get_server(settings: HashMap<String, String>) -> Rocket<Build> {
    // let settings = get_settings_as_map();
    let db_config = Config {
        db: get_db(settings.clone()),
    };
    let x = PublicGotham::new();
    rocket::Rocket::build()
        .mount("/", routes![crate::engine::traits::wrap_keygen_first])
        .manage(Mutex::new(Box::new(x) as Box<dyn crate::engine::traits::Db>))
        .manage(db_config)
}

fn get_db(settings: HashMap<String, String>) -> DB {
    let db_name = settings.get("db_name").unwrap_or(&"db".to_string()).clone();
    if !db_name.chars().all(|e| char::is_ascii_alphanumeric(&e)) {
        panic!("DB name is illegal, may only contain alphanumeric characters");
    }

    DB::Local(rocksdb::DB::open_default(format!("./{}", db_name)).unwrap())
}
