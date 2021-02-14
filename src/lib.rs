//! Pet-Pit
//!
//! Initial Version by: Olivier Blazy olivier@blazy.eu
//! # Examples
//!
//! ```
//! # // TODO (if you put code here it'll run as a test and also show up
//! # //     in the crate-level documentation!)
//! ```

extern crate curve25519_dalek;
extern crate rand_core;
extern crate rand_os;
//extern crate rand;
extern crate bencher;


mod petpit;
mod petpiteq;
mod rspeq;
mod sigpeq;


pub use crate::petpit::*;
pub use crate::petpiteq::*;
pub use crate::rspeq::*;
pub use crate::sigpeq::*;
