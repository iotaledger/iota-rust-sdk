// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Dynamic fields API implementation.

use std::sync::Arc;

use iota_sdk::{grpc_client::read_mask_fields::DynamicFieldReadMask, grpc_types::v1 as proto};

use crate::{
    error::{Result, SdkFfiError},
    grpc::client::GrpcClient,
    types::object::{Object, ObjectId},
};

/// The kind of a dynamic field.
#[derive(uniffi::Enum)]
pub enum DynamicFieldKind {
    /// The kind of the dynamic field is unknown.
    Unknown,
    /// A dynamic field.
    Field,
    /// A dynamic object field.
    Object,
}

impl From<proto::dynamic_field::dynamic_field::DynamicFieldKind> for DynamicFieldKind {
    fn from(value: proto::dynamic_field::dynamic_field::DynamicFieldKind) -> Self {
        match value {
            proto::dynamic_field::dynamic_field::DynamicFieldKind::Field => Self::Field,
            proto::dynamic_field::dynamic_field::DynamicFieldKind::Object => Self::Object,
            _ => Self::Unknown,
        }
    }
}

/// A dynamic field of an object.
#[derive(uniffi::Record)]
pub struct DynamicField {
    /// The kind of the dynamic field.
    pub kind: Option<DynamicFieldKind>,
    /// The id of the dynamic field's parent object.
    pub parent: Option<Arc<ObjectId>>,
    /// The id of the dynamic field object.
    pub field_id: Option<Arc<ObjectId>>,
    /// The dynamic field object itself.
    pub field_object: Option<Arc<Object>>,
    /// The BCS representation of the dynamic field's name.
    pub name_bcs: Option<Vec<u8>>,
    /// The BCS representation of the dynamic field's value.
    ///
    /// For regular dynamic fields this contains the BCS-encoded value whose
    /// type is given by `value_type`. For dynamic *object* fields this
    /// contains the BCS-encoded id of the child object; use `child_object`
    /// to access the full object.
    pub value_bcs: Option<Vec<u8>>,
    /// The type of the dynamic field's value.
    pub value_type: Option<String>,
    /// The id of the child object when a child is a dynamic object field.
    pub child_id: Option<Arc<ObjectId>>,
    /// The object itself when a child is a dynamic object field.
    pub child_object: Option<Arc<Object>>,
}

impl TryFrom<&proto::dynamic_field::DynamicField> for DynamicField {
    type Error = SdkFfiError;

    fn try_from(value: &proto::dynamic_field::DynamicField) -> Result<Self> {
        Ok(Self {
            kind: value
                .kind
                .and_then(|kind| {
                    proto::dynamic_field::dynamic_field::DynamicFieldKind::try_from(kind).ok()
                })
                .map(Into::into),
            parent: value
                .parent
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            field_id: value
                .field_id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            field_object: value
                .field_object
                .as_ref()
                .filter(|object| object.bcs.is_some())
                .map(|object| object.object().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            name_bcs: value.name.as_ref().map(Vec::from),
            value_bcs: value.value.as_ref().map(Vec::from),
            value_type: value.value_type.clone(),
            child_id: value
                .child_id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            child_object: value
                .child_object
                .as_ref()
                .filter(|object| object.bcs.is_some())
                .map(|object| object.object().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
        })
    }
}

/// A page of dynamic fields returned by the gRPC server.
#[derive(uniffi::Record)]
pub struct DynamicFieldPage {
    /// The dynamic fields returned in the page.
    pub dynamic_fields: Vec<DynamicField>,
    /// Token to retrieve the next page. `None` when this is the last page.
    pub next_page_token: Option<Vec<u8>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// List a single page of dynamic fields of an object.
    ///
    /// Pass the returned `next_page_token` back in to retrieve the next page.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the parent and field id are returned.
    #[uniffi::method(default(page_size = None, page_token = None, read_mask = None))]
    pub async fn dynamic_fields(
        &self,
        parent: &ObjectId,
        page_size: Option<u32>,
        page_token: Option<Vec<u8>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<DynamicFieldPage> {
        let query = self.0.read().await.dynamic_fields(
            **parent,
            page_size,
            page_token.map(Into::into),
            crate::grpc::api::read_mask::<DynamicFieldReadMask>(&read_mask),
        );
        let page = query.await?.into_inner();
        Ok(DynamicFieldPage {
            dynamic_fields: page
                .items
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            next_page_token: page.next_page_token.map(|token| token.to_vec()),
        })
    }

    /// List all dynamic fields of an object, auto-paginating up to `limit`
    /// fields. If `limit` is `None`, all fields are returned.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the parent and field id are returned.
    #[uniffi::method(default(limit = None, read_mask = None))]
    pub async fn all_dynamic_fields(
        &self,
        parent: &ObjectId,
        limit: Option<u32>,
        read_mask: Option<Vec<String>>,
    ) -> Result<Vec<DynamicField>> {
        let query = self.0.read().await.dynamic_fields(
            **parent,
            None,
            None,
            crate::grpc::api::read_mask::<DynamicFieldReadMask>(&read_mask),
        );
        query
            .collect(limit)
            .await?
            .into_inner()
            .iter()
            .map(TryInto::try_into)
            .collect()
    }
}
