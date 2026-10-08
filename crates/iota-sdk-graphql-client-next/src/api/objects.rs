// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use cynic::{Operation, QueryBuilder, QueryFragment};
use iota_types::{Address, Object, ObjectId, Version};
#[cfg(feature = "move-types")]
use iota_types::{ObjectReference, Owner};

#[cfg(feature = "move-types")]
use crate::repr::Decoded;
use crate::{
    Error, GraphQLClient, Page, PageArgs, Paginated, Query, Request, Result, ServerVersion,
    TypeFilter,
    repr::{Bcs, Json},
    wire::{self, PageInfo, schema},
};

/// Query for [`GraphQLClient::object`].
#[derive(Clone, Debug)]
pub struct GetObject<R = Bcs> {
    object_id: ObjectId,
    version: Option<Version>,
    repr: PhantomData<fn() -> R>,
}

impl<R> GetObject<R> {
    fn with_repr<S>(self) -> GetObject<S> {
        GetObject {
            object_id: self.object_id,
            version: self.version,
            repr: PhantomData,
        }
    }
}

impl<R: ObjectRepr> Query for GetObject<R> {
    type Output = Option<R::Output>;
    type Data = ObjectQuery<R::Node>;
    type Variables = ObjectVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<Self::Data, ObjectVariables>> {
        Ok(ObjectQuery::build(ObjectVariables {
            object_id: self.object_id,
            version: self.version.map(|version| version.as_u64()),
        }))
    }

    fn decode(self, data: Self::Data) -> Result<Self::Output> {
        Ok(data.object.map(R::decode).transpose()?.flatten())
    }
}

impl<R> Request<GetObject<R>> {
    /// Fetch the object as it was at `version`, instead of its latest
    /// version.
    pub fn version(self, version: Version) -> Self {
        self.map(|query| GetObject {
            version: Some(version),
            ..query
        })
    }

    /// Return the JSON rendering of the object's contents, or `None` if the
    /// object is a package.
    pub fn json(self) -> Request<GetObject<Json>> {
        self.map(GetObject::with_repr)
    }

    /// Decode the object into `T`, the Rust mirror of its Move type. Fails
    /// with [`Error::InvalidInput`] if the object has a different type.
    #[cfg(feature = "move-types")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "move-types")))]
    pub fn decode<T: iota_move_types::MoveObject>(self) -> Request<GetObject<Decoded<T>>> {
        self.map(GetObject::with_repr)
    }
}

/// Query for [`GraphQLClient::objects`].
#[derive(Debug)]
pub struct ListObjects<R = Bcs> {
    owner: Option<Address>,
    type_filter: Option<TypeFilter>,
    object_ids: Option<Vec<ObjectId>>,
    page: PageArgs,
    repr: PhantomData<fn() -> R>,
}

impl<R> Clone for ListObjects<R> {
    fn clone(&self) -> Self {
        Self {
            owner: self.owner,
            type_filter: self.type_filter.clone(),
            object_ids: self.object_ids.clone(),
            page: self.page.clone(),
            repr: PhantomData,
        }
    }
}

impl ListObjects {
    pub(crate) fn new() -> Self {
        Self {
            owner: None,
            type_filter: None,
            object_ids: None,
            page: PageArgs::default(),
            repr: PhantomData,
        }
    }

    pub(crate) fn owned_by(owner: Address, type_filter: TypeFilter, page: PageArgs) -> Self {
        Self {
            owner: Some(owner),
            type_filter: Some(type_filter),
            page,
            ..Self::new()
        }
    }
}

impl<R> ListObjects<R> {
    #[cfg(feature = "move-types")]
    fn with_repr<S>(self) -> ListObjects<S> {
        ListObjects {
            owner: self.owner,
            type_filter: self.type_filter,
            object_ids: self.object_ids,
            page: self.page,
            repr: PhantomData,
        }
    }
}

impl<R: ObjectRepr> Query for ListObjects<R> {
    type Output = Page<R::Output>;
    type Data = ObjectsQuery<R::Node>;
    type Variables = ObjectsVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<Self::Data, ObjectsVariables>> {
        Ok(ObjectsQuery::build(ObjectsVariables {
            first: self.page.first(),
            after: self.page.after(),
            last: self.page.last(),
            before: self.page.before(),
            filter: Some(ObjectFilterInput {
                type_: R::type_filter(self.type_filter.as_ref()),
                owner: self.owner,
                object_ids: self.object_ids.clone(),
            }),
        }))
    }

    fn decode(self, data: Self::Data) -> Result<Self::Output> {
        let ObjectConnection { page_info, nodes } = data.objects;
        let items = nodes
            .into_iter()
            .map(|node| {
                R::decode(node)?.ok_or_else(|| {
                    Error::malformed("an object in the list has no contents to decode")
                })
            })
            .collect::<Result<_>>()?;
        Ok(Page::from_wire(items, page_info))
    }
}

impl<R: ObjectRepr> Paginated for ListObjects<R> {
    type Item = R::Output;

    fn page_args(&self) -> &PageArgs {
        &self.page
    }

    fn page_args_mut(&mut self) -> &mut PageArgs {
        &mut self.page
    }
}

impl<R> Request<ListObjects<R>> {
    /// Only return objects owned by `owner`.
    pub fn owner(self, owner: Address) -> Self {
        self.map(|query| ListObjects {
            owner: Some(owner),
            ..query
        })
    }

    /// Only return the objects with these ids.
    pub fn object_ids(self, object_ids: impl IntoIterator<Item = ObjectId>) -> Self {
        self.map(|query| ListObjects {
            object_ids: Some(object_ids.into_iter().collect()),
            ..query
        })
    }
}

impl Request<ListObjects> {
    /// Only return objects whose type matches `filter`.
    pub fn type_filter(self, filter: impl Into<TypeFilter>) -> Self {
        self.map(|query| ListObjects {
            type_filter: Some(filter.into()),
            ..query
        })
    }

    /// Only return objects of type `T`, decoded into it. Replaces any
    /// [`type_filter`](Self::type_filter).
    #[cfg(feature = "move-types")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "move-types")))]
    pub fn decode<T: iota_move_types::MoveObject>(self) -> Request<ListObjects<Decoded<T>>> {
        self.map(ListObjects::with_repr)
    }
}

impl GraphQLClient {
    /// An object, at its latest version unless
    /// [`version`](Request::<GetObject>::version) is set. Resolves to `None`
    /// if the object does not exist, or no longer does (e.g., after pruning).
    ///
    /// By default the object is returned as [`Object`]. Request another form
    /// with [`json`](Request::<GetObject>::json), or, with the `move-types`
    /// feature, `decode`.
    pub fn object(&self, object_id: ObjectId) -> Request<GetObject> {
        Request::new(
            self,
            GetObject {
                object_id,
                version: None,
                repr: PhantomData,
            },
        )
    }

    /// A page of objects, optionally filtered by
    /// [`owner`](Request::<ListObjects>::owner),
    /// [`type_filter`](Request::<ListObjects>::type_filter) or
    /// [`object_ids`](Request::<ListObjects>::object_ids).
    pub fn objects(&self) -> Request<ListObjects> {
        Request::new(self, ListObjects::new())
    }
}

/// An object decoded into the Rust mirror `T` of its Move type.
#[cfg(feature = "move-types")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "move-types")))]
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct DecodedObject<T> {
    /// The object's id, version and digest.
    pub reference: ObjectReference,
    /// Who owns the object.
    pub owner: Owner,
    /// The object's contents.
    pub value: T,
}

pub(crate) mod sealed {
    use cynic::QueryFragment;
    use serde::de::DeserializeOwned;

    use crate::{Result, TypeFilter, transport::MaybeSend, wire::schema};

    /// A form objects can be returned in: what to select, and how to decode
    /// it.
    pub trait ObjectRepr: MaybeSend + 'static {
        type Node: QueryFragment<SchemaType = schema::Object, VariablesFields = ()>
            + DeserializeOwned
            + MaybeSend;
        type Output: MaybeSend;

        /// The output, or `None` if the object has nothing to return in this
        /// form.
        fn decode(node: Self::Node) -> Result<Option<Self::Output>>;

        /// The type filter to send, given the one requested.
        fn type_filter(requested: Option<&TypeFilter>) -> Option<String> {
            requested.map(ToString::to_string)
        }
    }
}

use self::sealed::ObjectRepr;

impl ObjectRepr for Bcs {
    type Node = ObjectBcs;
    type Output = Object;

    fn decode(node: ObjectBcs) -> Result<Option<Object>> {
        let wire::Bcs(object) = node
            .bcs
            .ok_or_else(|| Error::malformed("an object has no BCS"))?;
        Ok(Some(object))
    }
}

impl ObjectRepr for Json {
    type Node = ObjectJson;
    type Output = serde_json::Value;

    fn decode(node: ObjectJson) -> Result<Option<serde_json::Value>> {
        Ok(node
            .as_move_object
            .and_then(|object| object.contents)
            .and_then(|contents| contents.json))
    }
}

#[cfg(feature = "move-types")]
impl<T> ObjectRepr for Decoded<T>
where
    T: iota_move_types::MoveObject + crate::transport::MaybeSend + 'static,
{
    type Node = ObjectBcs;
    type Output = DecodedObject<T>;

    fn decode(node: ObjectBcs) -> Result<Option<DecodedObject<T>>> {
        let Some(object) = Bcs::decode(node)? else {
            return Ok(None);
        };
        let reference = object.object_ref();
        let value = T::try_from(&object).map_err(|error| {
            Error::invalid_input(format!(
                "object {} cannot be decoded as {}: {error}",
                reference.object_id(),
                T::struct_tag()
            ))
        })?;
        Ok(Some(DecodedObject {
            reference,
            owner: *object.owner(),
            value,
        }))
    }

    fn type_filter(_: Option<&TypeFilter>) -> Option<String> {
        Some(T::struct_tag().to_string())
    }
}

#[derive(cynic::QueryVariables, Debug)]
pub struct ObjectVariables {
    pub(crate) object_id: ObjectId,
    pub(crate) version: Option<u64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectVariables")]
pub struct ObjectQuery<N>
where
    N: QueryFragment<SchemaType = schema::Object, VariablesFields = ()>,
{
    #[arguments(address: $object_id, version: $version)]
    pub(crate) object: Option<N>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct ObjectsVariables {
    pub(crate) first: Option<i32>,
    pub(crate) after: Option<String>,
    pub(crate) last: Option<i32>,
    pub(crate) before: Option<String>,
    pub(crate) filter: Option<ObjectFilterInput>,
}

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "ObjectFilter")]
pub struct ObjectFilterInput {
    #[cynic(rename = "type")]
    pub(crate) type_: Option<String>,
    pub(crate) owner: Option<Address>,
    pub(crate) object_ids: Option<Vec<ObjectId>>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "ObjectsVariables")]
pub struct ObjectsQuery<N>
where
    N: QueryFragment<SchemaType = schema::Object, VariablesFields = ()>,
{
    #[arguments(first: $first, after: $after, last: $last, before: $before, filter: $filter)]
    pub(crate) objects: ObjectConnection<N>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "ObjectConnection")]
pub(crate) struct ObjectConnection<N>
where
    N: QueryFragment<SchemaType = schema::Object, VariablesFields = ()>,
{
    pub(crate) page_info: PageInfo,
    pub(crate) nodes: Vec<N>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Object")]
pub struct ObjectBcs {
    pub(crate) bcs: Option<wire::Bcs<Object>>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Object")]
pub struct ObjectJson {
    pub(crate) as_move_object: Option<MoveObjectJson>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveObject")]
pub(crate) struct MoveObjectJson {
    pub(crate) contents: Option<MoveValueJson>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveValue")]
pub(crate) struct MoveValueJson {
    pub(crate) json: Option<serde_json::Value>,
}
