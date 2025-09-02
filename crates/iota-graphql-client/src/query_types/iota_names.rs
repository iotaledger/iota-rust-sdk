// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding;

use crate::{
    error::Error,
    query_types::{Address, Base64, GQLAddress, PageInfo, schema},
};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "ResolveIotaNamesAddressArgs"
)]
pub struct ResolveIotaNamesAddressQuery {
    #[arguments(name: $name)]
    pub resolve_iota_names_address: Option<GQLAddress>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct ResolveIotaNamesAddressArgs {
    pub name: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "IotaNamesRegistrationsArgs"
)]
pub struct IotaNamesAddressRegistrationsQuery {
    #[arguments(address: $address)]
    pub address: Option<IotaNamesRegistrationsQuery>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "IotaNamesDefaultNameArgs"
)]
pub struct IotaNamesAddressDefaultNameQuery {
    #[arguments(address: $address)]
    pub address: Option<IotaNamesDefaultNameQuery>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Address",
    variables = "IotaNamesRegistrationsArgs"
)]
pub struct IotaNamesRegistrationsQuery {
    #[arguments(after: $after, before: $before, first: $first, last: $last)]
    pub iota_names_registrations: NameRegistrationConnection,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct IotaNamesRegistrationsArgs {
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
pub struct IotaNamesDefaultNameQuery {
    #[arguments(format: $format)]
    pub iota_names_default_name: Option<String>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct IotaNamesDefaultNameArgs {
    pub address: Address,
    pub format: Option<NameFormat>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "NameRegistrationConnection")]
pub struct NameRegistrationConnection {
    pub page_info: PageInfo,
    pub nodes: Vec<NameRegistration>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "NameRegistration")]
pub struct NameRegistration {
    pub bcs: Option<Base64>,
}

impl TryFrom<NameRegistration> for iota_types::iota_names::NameRegistration {
    type Error = Error;

    fn try_from(value: NameRegistration) -> Result<Self, Self::Error> {
        let bytes = base64ct::Base64::decode_vec(
            value
                .bcs
                .ok_or_else(|| {
                    Error::from_error(crate::error::Kind::Deserialization, "bcs is missing")
                })?
                .0
                .as_str(),
        )?;
        bcs::from_bytes::<iota_types::Object>(&bytes)?
            .to_rust()
            .map_err(|e| Error::from_error(crate::error::Kind::Deserialization, e))
    }
}

#[derive(cynic::Enum, Debug, Clone, Copy)]
#[cynic(
    schema = "rpc",
    graphql_type = "NameFormat",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum NameFormat {
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
