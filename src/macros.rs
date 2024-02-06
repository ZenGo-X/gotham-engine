use rocket::info;
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
        .unwrap_or_else(|err| { panic!(
            "Failed to get from {} with customerId: {}, id: {} with error:\n{}",
            stringify!($enum_ident),
            $id,
            $customer_id,
            err
        )})
    }
}

fn db_get() {

}


// TODO: find a way to prevent code duplication.
// With macro invocation inside a macro there is the error:
// "type annotations needed"
#[macro_export]
macro_rules! db_get_required {
    ($db:expr, $customer_id:expr, $id:expr, $enum_ident:ident) => {
        $db.get(
            &crate::types::DbIndex {
                customerId: $customer_id.to_string(),
                id: $id.to_string(),
            },
            &EcdsaStruct::$enum_ident,
        )
        .await
        .unwrap_or_else(|err| { panic!(
            "Failed to get from {} with customerId: {}, id: {} with error:\n{}",
            stringify!($enum_ident),
            $id,
            $customer_id,
            err
        )})
        .unwrap_or_else(|| { panic!(
            "Value from {} with customerId: {}, id: {} is required",
            stringify!($enum_ident),
            $id,
            $customer_id,
        )})
    }
}





#[macro_export]
macro_rules! db_insert {
    ($db:expr, $customer_id:expr, $id:expr, $enum_ident:ident, $new_value:expr) => {
        {
        $db.insert(
            &crate::types::DbIndex {
                customerId: $customer_id.to_string(),
                id: $id.to_string(),
            },
            &crate::types::EcdsaStruct::$enum_ident,
            $new_value,
        )
        .await
        .or(Err(format!(
            "Failed to insert into {} with customerId: {}, id: {}",
            stringify!($enum_ident),
            $id,
            $customer_id,
        )))?
    }
    };
}

//TODO: db_insert abort after error

#[macro_export]
macro_rules! db_cast {
    ($value:expr, $cast_type:ty) => {
        $value.as_any().downcast_ref::<$cast_type>().unwrap_or_else(|| {
            panic!("Unable to cast to {}", stringify!($cast_type));
        })
    };
}
