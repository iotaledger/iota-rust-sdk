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
    api::define_query,
    error::{GraphQLError, GraphQLResult},
    pagination::{Page, PaginationFilter, PaginationFilterResponse},
    query_types::{
        IotaNamesAddressDefaultNameQueryFragment, IotaNamesAddressRegistrationsQueryFragment,
        IotaNamesDefaultNameArgs, IotaNamesDefaultNameQueryFragment, IotaNamesRegistrationsArgs,
        IotaNamesRegistrationsQueryFragment, ResolveIotaNamesAddressArgs,
        ResolveIotaNamesAddressQueryFragment,
    },
};

define_query! {
    /// Query for [`GraphQLClient::iota_names_registrations`]. Await it to send
    /// the request.
    pub struct ListIotaNamesRegistrationsQuery {
        client: GraphQLClient,
        address: Address,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<NameRegistration>>;
}

impl ListIotaNamesRegistrationsQuery {
    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    fn operation(
        address: Address,
        pagination: PaginationFilterResponse,
    ) -> cynic::Operation<IotaNamesAddressRegistrationsQueryFragment, IotaNamesRegistrationsArgs>
    {
        IotaNamesAddressRegistrationsQueryFragment::build(IotaNamesRegistrationsArgs {
            address,
            after: pagination.after,
            before: pagination.before,
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<NameRegistration>> {
        let Self {
            client,
            pagination,
            address,
        } = self;
        let pagination = client.pagination_filter(pagination).await;
        let response = client
            .run_query(&Self::operation(address, pagination))
            .await?;

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
}

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
    pub fn iota_names_registrations(&self, address: Address) -> ListIotaNamesRegistrationsQuery {
        ListIotaNamesRegistrationsQuery {
            client: self.clone(),
            address,
            pagination: PaginationFilter::default(),
        }
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iota_types::Address;

    use crate::test_utils::{
        assert_backward_page, assert_forward_page, backward_page, forward_page, sent_variables,
    };

    #[tokio::test]
    async fn iota_names_registrations_sends_the_address_and_pagination() {
        let vars = sent_variables(
            "IotaNamesAddressRegistrationsQueryFragment",
            |client| async move {
                let _ = client
                    .iota_names_registrations(Address::FRAMEWORK)
                    .pagination(backward_page())
                    .await;
            },
        )
        .await;
        assert_eq!(vars["address"], Address::FRAMEWORK.to_string());
        assert_backward_page(&vars);

        let vars = sent_variables(
            "IotaNamesAddressRegistrationsQueryFragment",
            |client| async move {
                let _ = client
                    .iota_names_registrations(Address::FRAMEWORK)
                    .pagination(forward_page())
                    .await;
            },
        )
        .await;
        assert_forward_page(&vars);
    }
}
