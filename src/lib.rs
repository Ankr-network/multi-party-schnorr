/*
    Multisig Schnorr

    Copyright 2018 by Kzen Networks

    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multisig-schnorr/blob/master/LICENSE>
*/

extern  crate aes_gcm;
extern crate centipede;
extern crate curv;
extern crate curve25519_dalek;
extern crate ecies_ed25519;
extern crate openssl;
extern crate openssl_sys;
extern crate proc_macro;
extern crate rand;
extern crate schnorrkel;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate typenum;


use std::fmt;

pub mod protocols;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}

impl std::error::Error for Error {}
