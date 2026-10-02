// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use cynic::{Operation, QueryBuilder};
use iota_types::{Address, Identifier, ObjectId, StructTag, TransactionDigest};

use crate::{
    Error, GraphQLClient, ModuleFilter, Page, PageArgs, Paginated, Query, Request, Result,
    ServerVersion, TypeFilter,
    wire::{AddressOnly, Bytes, DateTime, MoveTypeRepr, PageInfo, TransactionDigestOnly, schema},
};

/// An event a transaction emitted.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Event {
    /// The package of the module that emitted the event.
    pub package_id: Option<ObjectId>,
    /// The module that emitted the event.
    pub module: Option<Identifier>,
    /// The sender of the transaction that emitted the event.
    pub sender: Option<Address>,
    /// The event's Move type.
    pub event_type: StructTag,
    /// The BCS of the event's contents.
    pub contents: Vec<u8>,
    /// The JSON rendering of the event's contents.
    pub json: serde_json::Value,
    /// When the event was emitted, as an ISO 8601 timestamp.
    pub timestamp: Option<String>,
    /// The digest of the transaction that emitted the event.
    pub transaction_digest: Option<TransactionDigest>,
}

impl Event {
    fn decode(node: EventNode) -> Result<Self> {
        let (package_id, module) = match node.sending_module {
            Some(module) => (
                Some(ObjectId::from(module.package.address)),
                Some(Identifier::new(&module.name).map_err(|error| {
                    Error::malformed_with(format!("invalid module name `{}`", module.name), error)
                })?),
            ),
            None => (None, None),
        };
        let event_type = StructTag::from_str(&node.type_.repr).map_err(|error| {
            Error::malformed_with(format!("invalid event type `{}`", node.type_.repr), error)
        })?;
        let transaction_digest = node
            .transaction_block
            .and_then(|block| block.digest)
            .map(|digest| {
                TransactionDigest::from_str(&digest).map_err(|error| {
                    Error::malformed_with(format!("invalid transaction digest `{digest}`"), error)
                })
            })
            .transpose()?;
        Ok(Self {
            package_id,
            module,
            sender: node.sender.map(|sender| sender.address),
            event_type,
            contents: node.bcs.0,
            json: node.json,
            timestamp: node.timestamp.map(|timestamp| timestamp.0),
            transaction_digest,
        })
    }
}

/// Query for [`GraphQLClient::events`].
#[derive(Clone, Debug, Default)]
pub struct ListEvents {
    filter: EventFilterInput,
    page: PageArgs,
}

impl Query for ListEvents {
    type Output = Page<Event>;
    type Data = EventsQuery;
    type Variables = EventsVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<EventsQuery, EventsVariables>> {
        Ok(EventsQuery::build(EventsVariables {
            first: self.page.first(),
            after: self.page.after(),
            last: self.page.last(),
            before: self.page.before(),
            filter: Some(self.filter.clone()),
        }))
    }

    fn decode(self, data: EventsQuery) -> Result<Page<Event>> {
        let EventConnection { page_info, nodes } = data.events;
        let items = nodes
            .into_iter()
            .map(Event::decode)
            .collect::<Result<_>>()?;
        Ok(Page::from_wire(items, page_info))
    }
}

impl Paginated for ListEvents {
    type Item = Event;

    fn page_args(&self) -> &PageArgs {
        &self.page
    }

    fn page_args_mut(&mut self) -> &mut PageArgs {
        &mut self.page
    }
}

impl Request<ListEvents> {
    fn filter(self, f: impl FnOnce(&mut EventFilterInput)) -> Self {
        self.map(|mut query| {
            f(&mut query.filter);
            query
        })
    }

    /// Only return events from transactions `sender` sent.
    pub fn sender(self, sender: Address) -> Self {
        self.filter(|filter| filter.sender = Some(sender))
    }

    /// Only return events the transaction with `digest` emitted.
    pub fn transaction(self, digest: TransactionDigest) -> Self {
        self.filter(|filter| filter.transaction_digest = Some(digest.to_string()))
    }

    /// Only return events emitted by a module matching `module`.
    pub fn emitting_module(self, module: ModuleFilter) -> Self {
        self.filter(|filter| filter.emitting_module = Some(module.to_string()))
    }

    /// Only return events whose type matches `event_type`.
    pub fn event_type(self, event_type: impl Into<TypeFilter>) -> Self {
        let event_type = event_type.into().to_string();
        self.filter(|filter| filter.event_type = Some(event_type))
    }
}

impl GraphQLClient {
    /// A page of events, optionally filtered.
    pub fn events(&self) -> Request<ListEvents> {
        Request::new(self, ListEvents::default())
    }
}

#[derive(cynic::QueryVariables, Debug)]
pub struct EventsVariables {
    pub(crate) first: Option<i32>,
    pub(crate) after: Option<String>,
    pub(crate) last: Option<i32>,
    pub(crate) before: Option<String>,
    pub(crate) filter: Option<EventFilterInput>,
}

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "EventFilter")]
pub struct EventFilterInput {
    pub(crate) sender: Option<Address>,
    pub(crate) transaction_digest: Option<String>,
    pub(crate) emitting_module: Option<String>,
    pub(crate) event_type: Option<String>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "EventsVariables")]
pub struct EventsQuery {
    #[arguments(first: $first, after: $after, last: $last, before: $before, filter: $filter)]
    pub(crate) events: EventConnection,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "EventConnection")]
pub(crate) struct EventConnection {
    pub(crate) page_info: PageInfo,
    pub(crate) nodes: Vec<EventNode>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Event")]
pub(crate) struct EventNode {
    pub(crate) transaction_block: Option<TransactionDigestOnly>,
    pub(crate) sending_module: Option<ModuleNode>,
    pub(crate) sender: Option<AddressOnly>,
    #[cynic(rename = "type")]
    pub(crate) type_: MoveTypeRepr,
    pub(crate) bcs: Bytes,
    pub(crate) timestamp: Option<DateTime>,
    pub(crate) json: serde_json::Value,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveModule")]
pub(crate) struct ModuleNode {
    pub(crate) package: PackageAddress,
    pub(crate) name: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MovePackage")]
pub(crate) struct PackageAddress {
    pub(crate) address: Address,
}
