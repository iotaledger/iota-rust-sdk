// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use cynic::{Operation, QueryBuilder};
use iota_types::{Address, Identifier, StructTag, framework::Coin};

use crate::{
    Error, GraphQLClient, Page, PageArgs, Paginated, Query, Request, Result, ServerVersion,
    TypeFilter,
    api::objects::{ListObjects, ObjectBcs, ObjectsQuery, ObjectsVariables},
    wire::{MoveTypeRepr, Num, PageInfo, schema},
};

/// Query for [`GraphQLClient::coins`].
#[derive(Clone, Debug)]
pub struct ListCoins {
    owner: Address,
    coin_type: Option<StructTag>,
    page: PageArgs,
}

impl ListCoins {
    fn objects(&self) -> ListObjects {
        let coin = match &self.coin_type {
            Some(coin_type) => StructTag::new_coin(coin_type.clone()),
            None => StructTag::new(
                Address::FRAMEWORK,
                Identifier::from_static("coin"),
                Identifier::from_static("Coin"),
                Vec::new(),
            ),
        };
        ListObjects::owned_by(self.owner, TypeFilter::Type(coin), self.page.clone())
    }
}

impl Query for ListCoins {
    type Output = Page<Coin>;
    type Data = ObjectsQuery<ObjectBcs>;
    type Variables = ObjectsVariables;

    fn operation(
        &self,
        server_version: Option<&ServerVersion>,
    ) -> Result<Operation<Self::Data, ObjectsVariables>> {
        self.objects().operation(server_version)
    }

    fn decode(self, data: Self::Data) -> Result<Page<Coin>> {
        self.objects().decode(data)?.try_map(|object| {
            Coin::try_from_object(&object).map_err(|error| {
                Error::malformed_with("an object in the list is not a coin", error)
            })
        })
    }
}

impl Paginated for ListCoins {
    type Item = Coin;

    fn page_args(&self) -> &PageArgs {
        &self.page
    }

    fn page_args_mut(&mut self) -> &mut PageArgs {
        &mut self.page
    }
}

impl Request<ListCoins> {
    /// Only return coins of `coin_type`, e.g. `0x2::iota::IOTA`.
    pub fn coin_type(self, coin_type: StructTag) -> Self {
        self.map(|query| ListCoins {
            coin_type: Some(coin_type),
            ..query
        })
    }
}

/// The total balance of one coin type an address owns.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Balance {
    /// The coin type, e.g. `0x2::iota::IOTA`.
    pub coin_type: StructTag,
    /// The number of coin objects of this type the address owns.
    pub coin_object_count: u64,
    /// The sum of their balances.
    pub total_balance: u64,
}

impl Balance {
    fn decode(node: BalanceNode) -> Result<Self> {
        let coin_type = StructTag::from_str(&node.coin_type.repr).map_err(|error| {
            Error::malformed_with(
                format!("invalid coin type `{}`", node.coin_type.repr),
                error,
            )
        })?;
        Ok(Self {
            coin_type,
            coin_object_count: node.coin_object_count.unwrap_or_default(),
            total_balance: node.total_balance.map(Num::into_inner).unwrap_or_default(),
        })
    }
}

/// Query for [`GraphQLClient::balance`].
#[derive(Clone, Debug)]
pub struct GetBalance {
    owner: Address,
    coin_type: StructTag,
}

impl Query for GetBalance {
    type Output = Balance;
    type Data = BalanceQuery;
    type Variables = BalanceVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<BalanceQuery, BalanceVariables>> {
        Ok(BalanceQuery::build(BalanceVariables {
            owner: self.owner,
            coin_type: Some(self.coin_type.to_string()),
        }))
    }

    fn decode(self, data: BalanceQuery) -> Result<Balance> {
        match data.address.and_then(|address| address.balance) {
            Some(node) => Balance::decode(node),
            None => Ok(Balance {
                coin_type: self.coin_type,
                coin_object_count: 0,
                total_balance: 0,
            }),
        }
    }
}

impl Request<GetBalance> {
    /// The coin type to sum, e.g. `0x2::iota::IOTA`, the default.
    pub fn coin_type(self, coin_type: StructTag) -> Self {
        self.map(|query| GetBalance { coin_type, ..query })
    }
}

/// Query for [`GraphQLClient::balances`].
#[derive(Clone, Debug)]
pub struct ListBalances {
    owner: Address,
    page: PageArgs,
}

impl Query for ListBalances {
    type Output = Page<Balance>;
    type Data = BalancesQuery;
    type Variables = BalancesVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<BalancesQuery, BalancesVariables>> {
        Ok(BalancesQuery::build(BalancesVariables {
            owner: self.owner,
            first: self.page.first(),
            after: self.page.after(),
            last: self.page.last(),
            before: self.page.before(),
        }))
    }

    fn decode(self, data: BalancesQuery) -> Result<Page<Balance>> {
        let Some(AddressBalances { balances }) = data.address else {
            return Ok(Page::new(Vec::new(), false, false, None, None));
        };
        let items = balances
            .nodes
            .into_iter()
            .map(Balance::decode)
            .collect::<Result<_>>()?;
        Ok(Page::from_wire(items, balances.page_info))
    }
}

impl Paginated for ListBalances {
    type Item = Balance;

    fn page_args(&self) -> &PageArgs {
        &self.page
    }

    fn page_args_mut(&mut self) -> &mut PageArgs {
        &mut self.page
    }
}

impl GraphQLClient {
    /// A page of the coins `owner` owns, of every type unless
    /// [`coin_type`](Request::<ListCoins>::coin_type) is set.
    pub fn coins(&self, owner: Address) -> Request<ListCoins> {
        Request::new(
            self,
            ListCoins {
                owner,
                coin_type: None,
                page: PageArgs::default(),
            },
        )
    }

    /// The total balance of the IOTA coins `owner` owns, or of another type
    /// with [`coin_type`](Request::<GetBalance>::coin_type).
    pub fn balance(&self, owner: Address) -> Request<GetBalance> {
        Request::new(
            self,
            GetBalance {
                owner,
                coin_type: StructTag::new_gas(),
            },
        )
    }

    /// A page of the total balances of every coin type `owner` owns.
    pub fn balances(&self, owner: Address) -> Request<ListBalances> {
        Request::new(
            self,
            ListBalances {
                owner,
                page: PageArgs::default(),
            },
        )
    }
}

#[derive(cynic::QueryVariables, Debug)]
pub struct BalanceVariables {
    pub(crate) owner: Address,
    pub(crate) coin_type: Option<String>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "BalanceVariables")]
pub struct BalanceQuery {
    #[arguments(address: $owner)]
    pub(crate) address: Option<AddressBalance>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Address",
    variables = "BalanceVariables"
)]
pub(crate) struct AddressBalance {
    #[arguments(type: $coin_type)]
    pub(crate) balance: Option<BalanceNode>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct BalancesVariables {
    pub(crate) owner: Address,
    pub(crate) first: Option<i32>,
    pub(crate) after: Option<String>,
    pub(crate) last: Option<i32>,
    pub(crate) before: Option<String>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "BalancesVariables"
)]
pub struct BalancesQuery {
    #[arguments(address: $owner)]
    pub(crate) address: Option<AddressBalances>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Address",
    variables = "BalancesVariables"
)]
pub(crate) struct AddressBalances {
    #[arguments(first: $first, after: $after, last: $last, before: $before)]
    pub(crate) balances: BalanceConnection,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "BalanceConnection")]
pub(crate) struct BalanceConnection {
    pub(crate) page_info: PageInfo,
    pub(crate) nodes: Vec<BalanceNode>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Balance")]
pub(crate) struct BalanceNode {
    pub(crate) coin_type: MoveTypeRepr,
    pub(crate) coin_object_count: Option<u64>,
    pub(crate) total_balance: Option<Num<u64>>,
}
