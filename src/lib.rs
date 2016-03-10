//! Parse BGP messages.

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![no_std]
pub mod types;
pub mod bgp;
pub mod bmp;
mod afi;
mod safi;

