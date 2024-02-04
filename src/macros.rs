#[macro_export]
macro_rules! db_get {
    ($db:expr, $customer_id:expr, $id:expr, $enum_ident:ident) => {
        $db.get(
            &crate::types::DbIndex {
                customerId: $customer_id.to_string(),
                id: $id.to_string(),
            },
            &EcdsaStruct::$enum_ident,
        )
        .await
        .or(Err(format!(
            "Failed to get {} with customerId: {}, id: {} from db",
            $id,
            $customer_id,
            stringify!($enum_ident)
        )))?
        .ok_or(format!(
            "{} with customerId: {}, id: {} does not exist in db",
            $id,
            $customer_id,
            stringify!($enum_ident)
        ))?
    };
}

#[macro_export]
macro_rules! db_insert {
    ($db:expr, $customer_id:expr, $id:expr, $enum_ident:ident, $new_value:expr) => {
        $db.insert(
            &crate::types::DbIndex {
                customerId: $customer_id.to_string(),
                id: $id.to_string(),
            },
            &crate::types::EcdsaStruct::$enum_ident,
            &$new_value,
        )
        .await
        .or(Err(format!(
            "Failed to insert {} with customerId: {}, id: {} into db",
            $id,
            $customer_id,
            stringify!($enum_ident)
        )))?
    };
}

#[macro_export]
macro_rules! db_cast {
    ($value:expr, $cast_type:ty) => {
        $value.as_any().downcast_ref::<$cast_type>().unwrap()
    };
}
