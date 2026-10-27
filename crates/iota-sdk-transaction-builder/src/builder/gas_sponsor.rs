// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Defines the [`GasSponsor`] trait, which allows users to implement any
//! service that pays the gas for a transaction it did not send.

use std::future::Future;

use iota_types::{Address, ObjectReference, Transaction, TransactionDigest, UserSignature};

/// The gas payment a sponsor committed to for one transaction.
#[derive(Clone, Debug)]
pub struct SponsoredGas {
    /// The address paying for the transaction.
    pub owner: Address,
    /// The gas coins the sponsor put up.
    pub objects: Vec<ObjectReference>,
}

/// A service that pays the gas for someone else's transaction.
///
/// A sponsor hands out gas against a budget and later executes the transaction
/// that spends it, so it both funds and submits. Implement this to sponsor
/// through a service the SDK does not ship; for the IOTA gas station, use
/// [`GasStation`](crate::GasStation).
///
/// Pass an implementation to
/// [`execute_with_gas_sponsor`](crate::TransactionBuilder::execute_with_gas_sponsor).
pub trait GasSponsor {
    /// The error that can occur while sponsoring.
    type Error: 'static + std::error::Error + Send + Sync;

    /// Whatever the sponsor needs to recognize a reservation it handed out.
    /// The builder passes it back untouched and never interprets it.
    type Reservation;

    /// Reserve gas covering the transaction's gas needs.
    fn reserve_gas(
        &self,
        transaction: &Transaction,
    ) -> impl Future<Output = Result<(Self::Reservation, SponsoredGas), Self::Error>>;

    /// Execute a transaction against gas reserved by
    /// [`reserve_gas`](Self::reserve_gas).
    ///
    /// The transaction pays with the [`SponsoredGas`] that reservation
    /// returned, and `signature` is the sender's; the sponsor supplies its own.
    fn execute_reserved(
        &self,
        reservation: Self::Reservation,
        transaction: &Transaction,
        signature: &UserSignature,
    ) -> impl Future<Output = Result<TransactionDigest, Self::Error>>;
}
