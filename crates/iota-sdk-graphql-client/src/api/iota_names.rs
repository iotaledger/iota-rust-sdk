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
    GraphQLClient,
    error::{GraphQLError, GraphQLResult},
    pagination::{Page, PaginationFilter},
    query_types::{
        IotaNamesAddressDefaultNameQueryFragment, IotaNamesAddressRegistrationsQueryFragment,
        IotaNamesDefaultNameArgs, IotaNamesDefaultNameQueryFragment, IotaNamesRegistrationsArgs,
        IotaNamesRegistrationsQueryFragment, ResolveIotaNamesAddressArgs,
        ResolveIotaNamesAddressQueryFragment,
    },
};

impl GraphQLClient {
    /// Return the resolved address for the given name.
    pub async fn iota_names_lookup(&self, name: &str) -> GraphQLResult<Option<Address>> {
        let operation = ResolveIotaNamesAddressQueryFragment::build(ResolveIotaNamesAddressArgs {
            name: name.to_owned(),
        });
        let response = self.run_query(&operation).await?;

        let ResolveIotaNamesAddressQueryFragment {
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
    ) -> GraphQLResult<Page<NameRegistration>> {
        let pagination = self.pagination_filter(pagination_filter).await;
        let operation =
            IotaNamesAddressRegistrationsQueryFragment::build(IotaNamesRegistrationsArgs {
                address,
                after: pagination.after,
                before: pagination.before,
                first: pagination.first,
                last: pagination.last,
            });
        let response = self.run_query(&operation).await?;

        let IotaNamesAddressRegistrationsQueryFragment {
            address:
                Some(IotaNamesRegistrationsQueryFragment {
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
                .collect::<GraphQLResult<Vec<_>>>()?,
        ))
    }

    /// Get the default name pointing to this address, if one exists.
    pub async fn iota_names_default_name(
        &self,
        address: Address,
        format: impl Into<Option<NameFormat>>,
    ) -> GraphQLResult<Option<Name>> {
        let operation = IotaNamesAddressDefaultNameQueryFragment::build(IotaNamesDefaultNameArgs {
            address,
            format: format.into().map(Into::into),
        });
        let response = self.run_query(&operation).await?;

        let IotaNamesAddressDefaultNameQueryFragment {
            address:
                Some(IotaNamesDefaultNameQueryFragment {
                    iota_names_default_name: Some(name),
                }),
        } = response
        else {
            return Ok(None);
        };

        Ok(Some(Name::from_str(&name).map_err(|source| {
            GraphQLError::InvalidName { name, source }
        })?))
    }
}
