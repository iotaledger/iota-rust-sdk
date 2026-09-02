// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! IOTA Names API implementation.

use std::str::FromStr;

use cynic::QueryBuilder;
use iota_types::{
    Address,
    iota_names::{NameFormat, NameRegistration, name::Name},
};

use crate::{
    Client,
    error::{Error, Kind, Result},
    pagination::{Page, PaginationFilter},
    query_types::{
        AddressIotaNamesDefaultName, AddressIotaNamesRegistrations,
        IotaNamesAddressDefaultNameQuery, IotaNamesAddressRegistrationsQuery,
        IotaNamesDefaultNameArgs, IotaNamesRegistrationsArgs, ResolveIotaNamesAddressArgs,
        ResolveIotaNamesAddressQuery,
    },
};

impl Client {
    /// Return the resolved address for the given name.
    pub async fn iota_names_lookup(&self, name: &str) -> Result<Option<Address>> {
        let operation = ResolveIotaNamesAddressQuery::build(ResolveIotaNamesAddressArgs {
            name: name.to_owned(),
        });
        let response = self.run_query(&operation).await?;

        let ResolveIotaNamesAddressQuery {
            resolve_iota_names_address: Some(address),
        } = response
        else {
            return Ok(None);
        };

        Ok(Some(address.address))
    }

    /// Find all registration NFTs for the given address.
    pub async fn iota_names_registrations(
        &self,
        address: Address,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<NameRegistration>> {
        let pagination = self.pagination_filter(pagination_filter).await;
        let operation = IotaNamesAddressRegistrationsQuery::build(IotaNamesRegistrationsArgs {
            address,
            after: pagination.after,
            before: pagination.before,
            first: pagination.first,
            last: pagination.last,
        });
        let response = self.run_query(&operation).await?;

        let IotaNamesAddressRegistrationsQuery {
            address:
                Some(AddressIotaNamesRegistrations {
                    iota_names_registrations,
                }),
        } = response
        else {
            return Ok(Page::new_empty());
        };

        Ok(Page::new(
            iota_names_registrations.page_info,
            iota_names_registrations
                .nodes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>>>()?,
        ))
    }

    /// Get the default name pointing to this address, if one exists.
    pub async fn iota_names_default_name(
        &self,
        address: Address,
        format: impl Into<Option<NameFormat>>,
    ) -> Result<Option<Name>> {
        let operation = IotaNamesAddressDefaultNameQuery::build(IotaNamesDefaultNameArgs {
            address,
            format: format.into().map(Into::into),
        });
        let response = self.run_query(&operation).await?;

        let IotaNamesAddressDefaultNameQuery {
            address:
                Some(AddressIotaNamesDefaultName {
                    iota_names_default_name: Some(name),
                }),
        } = response
        else {
            return Ok(None);
        };

        Ok(Some(Name::from_str(&name).map_err(|_| {
            Error::from_error(Kind::Parse, format!("invalid name: {name}"))
        })?))
    }
}
