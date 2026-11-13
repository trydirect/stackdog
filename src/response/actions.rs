//! Response actions

use anyhow::Result;

/// Response action trait
pub trait Action {
    fn execute(&self) -> Result<()>;
    fn name(&self) -> &str;
}
