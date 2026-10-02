// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding;

use crate::{
    error::GraphQLError,
    query_types::{Address, Base64, GraphQLAddress, PageInfo, schema},
};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "ResolveIotaNamesAddressArgs"
)]
pub(crate) struct ResolveIotaNamesAddressQueryFragment {
    #[arguments(name: $name)]
    pub resolve_iota_names_address: Option<GraphQLAddress>,
}

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct ResolveIotaNamesAddressArgs {
    pub name: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "IotaNamesRegistrationsArgs"
)]
pub(crate) struct IotaNamesAddressRegistrationsQueryFragment {
    #[arguments(address: $address)]
    pub address: Option<IotaNamesRegistrationsQueryFragment>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "IotaNamesDefaultNameArgs"
)]
pub(crate) struct IotaNamesAddressDefaultNameQueryFragment {
    #[arguments(address: $address)]
    pub address: Option<IotaNamesDefaultNameQueryFragment>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Address",
    variables = "IotaNamesRegistrationsArgs"
)]
pub(crate) struct IotaNamesRegistrationsQueryFragment {
    #[arguments(after: $after, before: $before, first: $first, last: $last)]
    pub iota_names_registrations: NameRegistrationConnection,
}

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct IotaNamesRegistrationsArgs {
    pub address: Address,
    pub after: Option<String>,
    pub before: Option<String>,
    pub first: Option<i32>,
    pub last: Option<i32>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Address",
    variables = "IotaNamesDefaultNameArgs"
)]
pub(crate) struct IotaNamesDefaultNameQueryFragment {
    #[arguments(format: $format)]
    pub iota_names_default_name: Option<String>,
}

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct IotaNamesDefaultNameArgs {
    pub address: Address,
    pub format: Option<NameFormat>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "NameRegistrationConnection")]
pub(crate) struct NameRegistrationConnection {
    pub page_info: PageInfo,
    pub nodes: Vec<NameRegistration>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "NameRegistration")]
pub(crate) struct NameRegistration {
    pub bcs: Option<Base64>,
}

impl TryFrom<NameRegistration> for iota_types::iota_names::NameRegistration {
    type Error = GraphQLError;

    fn try_from(value: NameRegistration) -> Result<Self, Self::Error> {
        let bytes = base64ct::Base64::decode_vec(
            value
                .bcs
                .ok_or(GraphQLError::EmptyResponseField("name registration bcs"))?
                .0
                .as_str(),
        )?;
        bcs::from_bytes::<iota_types::Object>(&bytes)?
            .to_rust()
            .map_err(GraphQLError::deserialization)
    }
}

#[derive(Clone, Copy, cynic::Enum, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "NameFormat",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub(crate) enum NameFormat {
    At,
    Dot,
}

impl From<iota_types::iota_names::NameFormat> for NameFormat {
    fn from(value: iota_types::iota_names::NameFormat) -> Self {
        match value {
            iota_types::iota_names::NameFormat::At => NameFormat::At,
            iota_types::iota_names::NameFormat::Dot => NameFormat::Dot,
        }
    }
}
