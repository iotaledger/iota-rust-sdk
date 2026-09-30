// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! IOTA Names API implementation.

use std::str::FromStr;

use cynic::QueryBuilder;
use futures::Stream;
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
    streams::stream_paginated_query,
};

define_query! {
    /// Query for [`GraphQLClient::iota_names_registrations`]. Await it to send
    /// the request.
    #[derive(Clone)]
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

    /// Stream every item, page by page, starting at the pagination's cursor
    /// and in its direction, with its limit as the page size.
    pub fn stream(self) -> impl Stream<Item = GraphQLResult<NameRegistration>> {
        let pagination = self.pagination.clone();
        stream_paginated_query(move |page| self.clone().pagination(page).send(), pagination)
    }

    fn operation(
        &self,
        pagination: &PaginationFilterResponse,
    ) -> cynic::Operation<IotaNamesAddressRegistrationsQueryFragment, IotaNamesRegistrationsArgs>
    {
        IotaNamesAddressRegistrationsQueryFragment::build(IotaNamesRegistrationsArgs {
            address: self.address,
            after: pagination.after.clone(),
            before: pagination.before.clone(),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<NameRegistration>> {
        let pagination = self.client.pagination_filter(self.pagination.clone()).await;
        let response = self.client.run_query(&self.operation(&pagination)).await?;

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

define_query! {
    /// Query for [`GraphQLClient::iota_names_default_name`]. Await it to send
    /// the request.
    pub struct GetIotaNamesDefaultNameQuery {
        client: GraphQLClient,
        address: Address,
        format: Option<NameFormat>,
    }
    output: GraphQLResult<Option<Name>>;
}

impl GetIotaNamesDefaultNameQuery {
    /// Set the format of the returned name.
    pub fn format(mut self, format: impl Into<Option<NameFormat>>) -> Self {
        self.format = format.into();
        self
    }

    async fn send(self) -> GraphQLResult<Option<Name>> {
        let operation = IotaNamesAddressDefaultNameQueryFragment::build(IotaNamesDefaultNameArgs {
            address: self.address,
            format: self.format.map(Into::into),
        });
        let response = self.client.run_query(&operation).await?;

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
    pub fn iota_names_default_name(&self, address: Address) -> GetIotaNamesDefaultNameQuery {
        GetIotaNamesDefaultNameQuery {
            client: self.clone(),
            address,
            format: None,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iota_types::{Address, iota_names::NameFormat};

    use crate::test_utils::{assert_backward_page, backward_page, sent_variables};

    #[tokio::test]
    async fn iota_names_default_name_sends_the_address_and_format() {
        let vars = sent_variables(
            "IotaNamesAddressDefaultNameQueryFragment",
            |client| async move {
                let _ = client
                    .iota_names_default_name(Address::FRAMEWORK)
                    .format(NameFormat::Dot)
                    .await;
            },
        )
        .await;
        assert_eq!(vars["address"], Address::FRAMEWORK.to_string());
        assert_eq!(vars["format"], "DOT");

        let vars = sent_variables(
            "IotaNamesAddressDefaultNameQueryFragment",
            |client| async move {
                let _ = client.iota_names_default_name(Address::FRAMEWORK).await;
            },
        )
        .await;
        assert!(vars["format"].is_null());
    }

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
    }
}
