use rocket::request::{self, FromRequest, Request};
use rocket::{http::Status, outcome::Outcome};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
}
#[rocket::async_trait]
impl<'a> FromRequest<'a> for Claims {
    type Error = ();

    async fn from_request(request: &'a Request<'_>) -> request::Outcome<Self, Self::Error> {
        let customer_id_header: Vec<_> = request.headers().get("x-customer-id").collect();
        if let Some(customer_id) = customer_id_header.get(0) {
            // Deserialize the customer id as Claims
            let claims = Claims {
                sub: customer_id.to_string(),
            };
            Outcome::Success(claims)
        } else {
            // Handle the case when there are no Authorization headers
            Outcome::Error((Status::BadRequest, ()))
        }
    }
}
