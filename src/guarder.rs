use rocket::request::FromRequest;
use rocket::{outcome::Outcome, request, Request};

pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[rocket::async_trait]
impl<'a> FromRequest<'a> for Claims {
    type Error = ();

    async fn from_request(_request: &'a Request<'_>) -> request::Outcome<Self, Self::Error> {
        let claim = Claims {
            sub: "yes".to_string(),
            exp: 0,
        };

        Outcome::Success(claim)
    }
}
