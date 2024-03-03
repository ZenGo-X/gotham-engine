use rocket::info;
#[macro_export]
macro_rules! db_get {
    ($db:expr, $customer_id:expr, $id:expr, $enum_ident:ident) => {
        match $db.get(
            &crate::types::DbIndex {
                customerId:  $customer_id.to_string(),
                id: $id.to_string(),
            },
            &EcdsaStruct::$enum_ident,
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
                return Err(format!("Failed to get from {} with customerId: {}, id: {} with error:\n{}",
                    stringify!($enum_ident),
                    $customer_id,
                    $id,
                    err
                ));
            }
        }
        // .as_any().downcast_ref::<$cast_type>() {
        //     None => {
        //         Cast error
                // return Err(format!("Unable to cast to {}", stringify!($cast_type)))
            // }
            // Some(v) => { v.clone() }    // Cust success
        // }
    }
}



// TODO: find a way to prevent code duplication.
// With macro invocation inside a macro there is the error:
// "type annotations needed"
#[macro_export]
macro_rules! db_get_required {
    ($db:expr, $customer_id:expr, $id:expr, $enum_ident:ident, $cast_type:ty) => {
        match match $db.get(
            &crate::types::DbIndex {
                customerId:  $customer_id.to_string(),
                id: $id.to_string(),
            },
            &EcdsaStruct::$enum_ident,
        )
        .await
        {
            Ok(Some(val)) => { val }    // Db get success
            Ok(None) => {
                // Empty result
                return Err(format!("Value from {} with customerId: {}, id: {} is required",
                    stringify!($enum_ident),
                    $customer_id,
                    $id
                ));
            }
            Err(err) => {
                //Db error
                return Err(format!("Failed to get from {} with customerId: {}, id: {} with error:\n{}",
                    stringify!($enum_ident),
                    $customer_id,
                    $id,
                    err
                ));
            }
        }
        .as_any().downcast_ref::<$cast_type>() {
            None => {
                // Cast error
                return Err(format!("Unable to cast to {}", stringify!($cast_type)))
            }
            Some(v) => { v.clone() }    // Cust success
        }
    }
}





#[macro_export]
macro_rules! db_insert {
    ($db:expr, $customer_id:expr, $id:expr, $enum_ident:ident, $new_value:expr) => {
        match $db.insert(
            &crate::types::DbIndex {
                customerId: $customer_id.to_string(),
                id: $id.to_string(),
            },
            &crate::types::EcdsaStruct::$enum_ident,
            $new_value,
        )
        .await {
            Ok(_) => {},
            Err(err) => {
                return Err(format!("Failed to insert into {} with customerId: {}, id: {} with error:\n{}",
                    stringify!($enum_ident),
                    $customer_id,
                    $id,
                    err))
            }
        }
    };
}

//TODO: db_insert abort after error

#[macro_export]
macro_rules! db_cast {
    ($value:expr, $cast_type:ty) => {
      match $value.as_any().downcast_ref::<$cast_type>() {
            None => {
                // Cast error
                return Err(format!("Unable to cast to {}", stringify!($cast_type)))
            }
            Some(val) => { val.clone() }    // Cust success
        }
    };
}


/*
    let x = match result {
        Ok(Some(val)) => {
            match val.as_any().downcast_ref::<Abort>() {
                Some(v) => { v },
                None => {
                    // Incorrect Type
                    return Err(format!(""));
                }
            }
        }
        Ok(None) => {
            // Empty result
            return Err(format!(""));
        }
        Err(err) => {
            //Get error
            return Err(format!("{}",err));
        }
    };

     */
