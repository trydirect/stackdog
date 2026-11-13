//! Database module

pub mod baselines;
pub mod connection;
pub mod events;
pub mod models;
pub mod repositories;

pub use baselines::*;
pub use connection::{create_pool, init_database, DbPool};
pub use events::*;
pub use models::*;
pub use repositories::alerts::*;
pub use repositories::offenses::*;

/// Marker struct for module tests
pub struct DatabaseMarker;
