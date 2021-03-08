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
/// variant (2)
pub mod bitcoin_schnorr;
mod test_bitcoin;
mod test_schnorrkel;

/// variant (2)
/// Schnorr signature variants:
/// Elliptic Curve Schnorr signatures for message m and public key P (=xG where x is secret scalar in G) generally involve
/// a point R (=rG), integers r picked by the signer, and generator G which satisfy
/// k = scalar(m)
/// s = kx + r
/// Signatures are (R,s) that satisfy sG = R + kP.
pub mod schnorrkel;
mod tests;

