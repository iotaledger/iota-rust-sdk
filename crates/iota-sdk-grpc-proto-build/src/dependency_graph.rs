// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use prost_types::{DescriptorProto, field_descriptor_proto::Type};

/// Message dependencies of a package, keyed by fully qualified protobuf name.
#[derive(Debug, Default)]
pub(crate) struct DependencyGraph {
    dependencies: HashMap<String, HashSet<String>>,
}

impl DependencyGraph {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Adds `messages` and, recursively, their nested messages. `parent` is the
    /// fully qualified name of the enclosing package or message, with a
    /// leading dot.
    pub(crate) fn add_messages(&mut self, messages: &[DescriptorProto], parent: &str) {
        for message in messages {
            let full_name = format!("{parent}.{}", message.name());

            let dependencies = message
                .field
                .iter()
                .filter(|field| matches!(field.r#type(), Type::Message))
                .map(|field| field.type_name().to_owned());
            self.dependencies
                .entry(full_name.clone())
                .or_default()
                .extend(dependencies);

            self.add_messages(&message.nested_type, &full_name);
        }
    }

    // Check if there's a circular dependency between two messages
    pub(crate) fn has_circular_dependency(&self, from_message: &str, to_message: &str) -> bool {
        // If to_message can reach back to from_message, we have a cycle
        self.can_reach(to_message, from_message, &mut HashSet::new())
    }

    // Check if we can reach target from source (used for cycle detection)
    fn can_reach(&self, source: &str, target: &str, visited: &mut HashSet<String>) -> bool {
        if source == target {
            return true;
        }

        if visited.contains(source) {
            return false; // Already visited this node
        }

        visited.insert(source.to_string());

        if let Some(deps) = self.dependencies.get(source) {
            for dep in deps {
                if self.can_reach(dep, target, visited) {
                    return true;
                }
            }
        }

        false
    }
}
