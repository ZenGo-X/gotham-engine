# Gotham-engine

Gotham engine is the engine for gotham-city project. It abstracts through traits,
routes for keygen and sign in a 2P setting for Lindell17 protocol. The level of abstraction allows
the implementers to pass specific DB api and authorization policies. The engine provides default trait implementations
such that the implementers are only implementing the peripherals. Any potential change at the cryptographic protocol is done through the gotham-engine and and changes are reflected automatically at the implementers through default implementations. An example of usage is provided in the [gotham-city](https://github.com/ZenGo-X/gotham-city/) project.
## Example Workflow an implementer:
1. Instantiate empty traits for KeyGen and Sign:
   ```rust,no_run
   pub struct PublicGotham {
      rocksdb_client: rocksdb::DB,
   }
   impl KeyGen for PublicGotham {}
   impl Sign for PublicGotham {}
   ```
   
2. Implement the Db trait
```
   impl Db for PublicGotham {
    async fn insert(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
        value: &dyn Value,
    ) -> Result<(), DatabaseError> {
        ///implementation
    }

    async fn get(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
    ) -> Result<Option<Box<dyn Value>>, DatabaseError> {
           ///implementation
   }
   ```
3.  Implement the TxAuthorization trait
```
impl Txauthorization for Authorizer {
    /// the granted function implements the logic of tx authorization. If no tx authorization is needed the function returns always true
    fn granted(&self) -> Result<bool, DatabaseError> {
        Ok(true)
    }
}
```
4. Spin a rocket server and mount gotham-engine existing endpoints for keygen and sign
```
rocket::Rocket::build()
        .register("/", catchers![internal_error, not_found, bad_request])
        .mount(
            "/",
            routes![
                gotham_engine::routes::wrap_keygen_first,
                gotham_engine::routes::wrap_keygen_second,
                gotham_engine::routes::wrap_keygen_third,
                gotham_engine::routes::wrap_keygen_fourth,
                gotham_engine::routes::wrap_chain_code_first_message,
                gotham_engine::routes::wrap_chain_code_second_message,
                gotham_engine::routes::wrap_sign_first,
                gotham_engine::routes::wrap_sign_second,
            ],
        )
```
5. Pass to the gotham-engine the Db and TxAuthorization trait as dyn trait object
   ```
   .manage(Mutex::new(Box::new(x) as Box<dyn gotham_engine::traits::Db>))
        .manage(Mutex::new(
            Box::new(tx) as Box<dyn gotham_engine::traits::Txauthorization>
        ))
   ```

