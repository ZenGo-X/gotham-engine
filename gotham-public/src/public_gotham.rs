//!Public gotham implementation
use crate::engine::traits::*;
use crate::engine::types::*;
use rocket::async_trait;
use std::collections::HashMap;
pub struct PublicGotham {
    db_type: DbConnector,
    auth: Authenticator,
    rocksdb_client: rocksdb::DB,
}
pub struct Config {
    pub db: DB,
}
pub enum DB {
    Local(rocksdb::DB),
}

fn get_settings_as_map() -> HashMap<String, String> {
    let config_file = include_str!("../../Settings.toml");
    let mut settings = config::Config::default();
    settings
        .merge(config::File::from_str(
            config_file,
            config::FileFormat::Toml,
        ))
        .unwrap()
        .merge(config::Environment::new())
        .unwrap();

    settings.try_into::<HashMap<String, String>>().unwrap()
}
impl PublicGotham {
    pub fn new() -> Self {
        let settings = get_settings_as_map();
        let db_name = settings.get("db_name").unwrap_or(&"db".to_string()).clone();
        if !db_name.chars().all(|e| char::is_ascii_alphanumeric(&e)) {
            panic!("DB name is illegal, may only contain alphanumeric characters");
        }
        let rocksdb_client = rocksdb::DB::open_default(format!("./{}", db_name)).unwrap();

        PublicGotham {
            db_type: DbConnector::RocksDB,
            auth: Authenticator::None,
            rocksdb_client,
        }
    }
}

impl KeyGen for PublicGotham {}

impl<S: Db> Sign<S> for PublicGotham {}
fn idify(user_id: String, id: String, name: &dyn MPCStruct) -> String {
    format!("{}_{}_{}", user_id, id, name.to_string())
}
#[async_trait]
impl Db for PublicGotham {
    async fn insert(
        &self,
        key: &Db_index,
        table_name: &dyn MPCStruct,
        value: &dyn Value,
    ) -> Result<(), DatabaseError> {
        let identifier = idify(key.clone().customerId, key.clone().id, table_name);
        let v_string = &value.to_string();
        self.rocksdb_client.put(identifier, v_string);
        Ok(())
    }

    async fn get<'a, T: serde::de::Deserialize<'a>>(
        &self,
        key: &Db_index,
        table_name: &dyn MPCStruct,
    ) -> Result<Option<T>, DatabaseError> {
        Err(DatabaseError::InsertError(0))
    }
    async fn has_active_share(&self, user_id: &str) -> Result<bool, String> {
        Ok(false)
    }
}
