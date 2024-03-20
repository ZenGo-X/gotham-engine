use rocket::info;
#[macro_export]
macro_rules! db_get {
    ($db:expr, $customer_id:expr, $id:expr, $enum_ident:ident) => {
        match $db.get(
            &$crate::types::DbIndex {
                customerId:  $customer_id.to_string(),
                id: $id.to_string(),
            },
            &$crate::types::EcdsaStruct::$enum_ident,
        )
        .await
        {
            Ok(Some(val)) => { Some(val) }    // Db get success
            Ok(None) => {
                // Empty result
                None
            }
            Err(err) => {
                //Db error
                let txt = format!("Failed to get from {} with customerId: {}, id: {} with error:\n{}",
                    stringify!($enum_ident),
                    $customer_id,
                    $id,
                    err
                );
                return Err(txt);
            }
        }
    }
}

#[macro_export]
macro_rules! db_get_required {
    ($db:expr, $customer_id:expr, $id:expr, $enum_ident:ident, $cast_type:ty) => {
        match match $db.get(
            &$crate::types::DbIndex {
                customerId:  $customer_id.to_string(),
                id: $id.to_string(),
            },
            &$crate::types::EcdsaStruct::$enum_ident,
        )
        .await
        {
            Ok(Some(val)) => {
                // Db get success
                val
            }
            Ok(None) => {
                // Empty result
                let txt = format!("Value from {} with customerId: {}, id: {} is required",
                    stringify!($enum_ident),
                    $customer_id,
                    $id
                );
                println!("{}", txt);
                return Err(txt);
            }
            Err(err) => {
                //Db error
                let txt = format!("Failed to get from {} with customerId: {}, id: {} with error:\n{}",
                    stringify!($enum_ident),
                    $customer_id,
                    $id,
                    err
                );
                println!("{}", txt);
                return Err(txt);
            }
        }
        .as_any().downcast_ref::<$cast_type>() {
            None => {
                // Cast error
                let txt = format!("Unable to cast to {}", stringify!($cast_type));
                println!("{}", txt);
                return Err(txt)
            }
            Some(v) => { v.clone() }    // Cust success
        }
    }
}

#[macro_export]
macro_rules! db_insert {
    ($db:expr, $customer_id:expr, $id:expr, $enum_ident:ident, $new_value:expr) => {
        match $db.insert(
            &$crate::types::DbIndex {
                customerId: $customer_id.to_string(),
                id: $id.to_string(),
            },
            &$crate::types::EcdsaStruct::$enum_ident,
            $new_value,
        )
        .await {
            Ok(_) => { },
            Err(err) => {
                let txt = format!("Failed to insert into {} with customerId: {}, id: {} with error:\n{}",
                    stringify!($enum_ident),
                    $customer_id,
                    $id,
                    err);
                println!("{}", txt);
                return Err(txt)
            }
        }
    };
}

#[macro_export]
macro_rules! db_cast {
    ($value:expr, $cast_type:ty) => {
      match $value.as_any().downcast_ref::<$cast_type>() {
            None => {
                // Cast error
                let txt = format!("Unable to cast to {}", stringify!($cast_type));
                println!("{}", txt);
                return Err(txt)
            }
            Some(val) => { val.clone() }    // Cust success
        }
    };
}