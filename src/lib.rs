#[cfg(feature = "gotham_client")]
pub mod client;

#[cfg(feature = "gotham_server")]
pub mod server;
// type Result<T> = std::result::Result<T, failure::Error>;
