// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use prost_types::FieldMask;

use super::{
    FIELD_PATH_SEPARATOR, FIELD_PATH_WILDCARD, FIELD_SEPARATOR, FieldMaskUtil, is_valid_path,
};

#[derive(Clone, Debug, Default)]
pub struct FieldMaskTree {
    wildcard: bool,
    root: Node,
}

#[derive(Clone, Debug, Default)]
struct Node {
    /// This node selects every field below it (a bare path terminated here).
    ///
    /// A node can be both a wildcard and carry explicit children: that is how
    /// "all of a parent, **plus** an explicit-only field" is represented (see
    /// [`FieldMaskTree::add_field_path_with_exceptions`]).
    wildcard: bool,
    children: BTreeMap<String, Node>,
}

impl Node {
    /// Whether this subtree selects any explicit-only leaf — a path whose final
    /// component is one of `exceptions`. Such a selection is not covered by an
    /// ancestor wildcard, so it must survive when a parent becomes a wildcard.
    fn selects_exception(&self, exceptions: &[&str]) -> bool {
        self.children.iter().any(|(name, child)| {
            exceptions.contains(&name.as_str()) || child.selects_exception(exceptions)
        })
    }
}

impl FieldMaskTree {
    pub fn new_wildcard() -> Self {
        Self {
            wildcard: true,
            root: Default::default(),
        }
    }

    pub fn add_field_path(&mut self, path: &str) -> &mut Self {
        self.add_field_path_with_exceptions(path, &[])
    }

    /// Adds `path`, treating any field named in `exceptions` as **not** covered
    /// by an ancestor wildcard.
    ///
    /// Normally a parent path subsumes its children, so `[a, a.b]` normalizes
    /// to `a` and the node at `a` is a plain wildcard. For an explicit-only
    /// field — one the server renders only when named by its leaf (`json`,
    /// `display`, `json_name`, `json_contents`) — that collapse would
    /// silently drop the request. When the leaf of `path` is in
    /// `exceptions`, it is kept alongside the parent instead: the parent
    /// node stays a wildcard (so its ordinary fields are still selected)
    /// and additionally carries the explicit leaf, so `[output_objects,
    /// output_objects.json]` selects every output-object field **and** the
    /// rendered `json`.
    pub fn add_field_path_with_exceptions(&mut self, path: &str, exceptions: &[&str]) -> &mut Self {
        if self.wildcard || !is_valid_path(path) {
            return self;
        }

        if path == FIELD_PATH_WILDCARD {
            self.wildcard = true;
            self.root.children.clear();
            return self;
        }

        // The leaf decides whether an ancestor wildcard subsumes this path.
        let leaf = path.rsplit(FIELD_SEPARATOR).next().unwrap_or(path);
        let keep_under_wildcard = exceptions.contains(&leaf);

        let mut node = &mut self.root;
        let mut components = path.split(FIELD_SEPARATOR).peekable();
        while let Some(component) = components.next() {
            // An ancestor that already selects everything below it subsumes this
            // path — unless the path targets an explicit-only leaf, which a
            // wildcard does not include.
            if node.wildcard && !keep_under_wildcard {
                return self;
            }

            let is_last = components.peek().is_none();
            node = node.children.entry(component.to_owned()).or_default();

            if is_last {
                node.wildcard = true;
                // Drop sub-selections now subsumed by this wildcard, but keep any
                // that still target an explicit-only leaf.
                node.children.retain(|name, child| {
                    exceptions.contains(&name.as_str()) || child.selects_exception(exceptions)
                });
            }
        }
        self
    }

    pub fn from_field_mask(mask: &FieldMask) -> Self {
        Self::from_field_mask_with_exceptions(mask, &[])
    }

    /// Builds a tree from `mask`, keeping explicit-only leaves (those named in
    /// `exceptions`) alongside any parent path, per
    /// [`add_field_path_with_exceptions`](Self::add_field_path_with_exceptions).
    pub fn from_field_mask_with_exceptions(mask: &FieldMask, exceptions: &[&str]) -> Self {
        let mut tree = Self::default();
        for path in &mask.paths {
            tree.add_field_path_with_exceptions(path, exceptions);
        }
        tree
    }

    pub fn to_field_mask(&self) -> FieldMask {
        let mut paths = Vec::new();
        Self::collect_field_paths(&self.root, &mut String::new(), &mut paths);
        FieldMask { paths }
    }

    fn collect_field_paths(node: &Node, path: &mut String, paths: &mut Vec<String>) {
        // A node that selects everything below it contributes its own path (the
        // empty path is the tree root, which is never emitted).
        if node.wildcard && !path.is_empty() {
            paths.push(path.clone());
        }

        // Explicit children — sub-selections and explicit-only extras — each
        // contribute their own paths.
        let parent_path_len = path.len();
        for (part, child) in node.children.iter() {
            if path.is_empty() {
                path.push_str(part);
            } else {
                path.push(FIELD_SEPARATOR);
                path.push_str(part);
            };
            Self::collect_field_paths(child, path, paths);
            path.truncate(parent_path_len);
        }
    }

    /// Checks if the provided path is contained in this FieldMaskTree.
    ///
    /// A path is considered a match and contained by this tree if it is a
    /// prefix for any contained paths, including if it is an exact match.
    ///
    /// ```
    /// # use iota_sdk_grpc_types::field::FieldMaskTree;
    /// let mut tree = FieldMaskTree::default();
    /// tree.add_field_path("foo.bar");
    ///
    /// assert!(tree.contains("foo"));
    /// assert!(tree.contains("foo.bar"));
    /// assert!(!tree.contains("foo.baz"));
    /// ```
    pub fn contains<P: AsRef<str>>(&self, path: P) -> bool {
        let path = path.as_ref();

        if path.is_empty() {
            return false;
        }

        if self.wildcard {
            return true;
        }

        let mut node = &self.root;
        for component in path.split(FIELD_SEPARATOR) {
            // If this node selects everything below it, any deeper path is a hit.
            if node.wildcard {
                return true;
            }

            if let Some(child) = node.children.get(component) {
                node = child;
            } else {
                return false;
            }
        }

        // We found a matching node for this path. This node may be a wildcard or
        // have explicit children. In either case the provided path is a "match"
        // and is contained by this tree.
        true
    }

    /// The explicitly named child fields of this (sub)tree, whether or not the
    /// node is also a wildcard.
    ///
    /// Unlike [`map_keys`](Self::map_keys) — which reports `None`/"no filter"
    /// for a wildcard — this still lists a wildcard node's explicit-only
    /// extras (an `output_objects.json` leaf selected alongside a bare
    /// `output_objects`). It is what the server's explicit-only field gate
    /// reads.
    pub fn explicit_children(&self) -> impl Iterator<Item = &str> {
        self.root.children.keys().map(String::as_str)
    }

    /// Returns the explicit map keys requested in this subtree, or `None` if
    /// this tree is a wildcard (no explicit key filter).
    ///
    /// When a user specifies explicit map keys via a field mask (e.g.
    /// `attributes.max_tx_gas`), this method returns an iterator over those
    /// key names. When the tree is a wildcard, `None` is returned to indicate
    /// "no filter — return all (or none, per policy)".
    pub fn map_keys(&self) -> Option<impl Iterator<Item = &str>> {
        if self.wildcard {
            None
        } else {
            Some(self.root.children.keys().map(String::as_str))
        }
    }

    /// Determines which entries of an inner map field should be included.
    ///
    /// Call this on the subtree rooted at a **map-wrapper message field**
    /// (e.g. the subtree at `feature_flags` or `attributes` inside
    /// `ProtocolConfig`) and pass the name of the **inner map field** (e.g.
    /// `"flags"` or `"attributes"`).  The return value tells the caller what
    /// to put in the resulting map:
    ///
    /// - `None` — the wrapper itself was a wildcard *or* the inner field was
    ///   not explicitly requested → **omit the wrapper field entirely** (leave
    ///   it as `None` in the response so clients can distinguish "not
    ///   requested" from "empty").
    /// - `Some(None)` — the inner field was requested without specific keys
    ///   (e.g. `feature_flags.flags`) → include **all entries**.
    /// - `Some(Some(keys))` — only these specific keys were requested (e.g.
    ///   `feature_flags.flags.flag_a`) → include **only those entries**.
    pub fn map_field_filter(
        &self,
        inner_field_name: &str,
    ) -> Option<Option<std::collections::HashSet<String>>> {
        match self.map_keys() {
            // Wildcard at the wrapper level (e.g. bare "feature_flags") → empty
            None => None,
            Some(_) => match self.subtree(inner_field_name) {
                // Inner field not among the requested children → empty
                None => None,
                Some(inner) => match inner.map_keys() {
                    // Inner field requested without specific keys → all entries
                    None => Some(None),
                    // Specific keys requested
                    Some(keys) => Some(Some(keys.map(String::from).collect())),
                },
            },
        }
    }

    pub fn subtree<P: AsRef<str>>(&self, path: P) -> Option<Self> {
        let path = path.as_ref();

        if path.is_empty() {
            return None;
        }

        let mut node = &self.root;
        // Whether the region at the current node is selected whole. The
        // tree-level wildcard makes the root such a region; otherwise a node's
        // own `wildcard` flag does. A wildcard node may still carry explicit
        // children, so matching children is tried first.
        let mut region_wildcard = self.wildcard;
        for component in path.split(FIELD_SEPARATOR) {
            match node.children.get(component) {
                Some(child) => {
                    region_wildcard = child.wildcard;
                    node = child;
                }
                // No explicit child: if the region is a wildcard the path is
                // covered wholesale, otherwise it is not selected at all.
                None => {
                    return region_wildcard.then(Self::new_wildcard);
                }
            }
        }

        Some(Self {
            wildcard: region_wildcard,
            root: node.clone(),
        })
    }
}

impl From<FieldMask> for FieldMaskTree {
    fn from(mask: FieldMask) -> Self {
        Self::from_field_mask(&mask)
    }
}

impl From<FieldMaskTree> for FieldMask {
    fn from(tree: FieldMaskTree) -> Self {
        tree.to_field_mask()
    }
}

impl std::fmt::Display for FieldMaskTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        FieldMaskUtil::display(&self.to_field_mask()).fmt(f)
    }
}

impl std::str::FromStr for FieldMaskTree {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut tree = Self::default();

        for path in s.split(FIELD_PATH_SEPARATOR) {
            tree.add_field_path(path);
        }

        Ok(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_field_path() {
        let mut tree = FieldMaskTree::default();

        assert!(tree.to_string().is_empty());
        tree.add_field_path("");
        assert!(tree.to_string().is_empty());

        tree.add_field_path("foo");
        assert_eq!(tree.to_string(), "foo");
        // redundant path
        tree.add_field_path("foo");
        assert_eq!(tree.to_string(), "foo");

        tree.add_field_path("bar.baz");
        assert_eq!(tree.to_string(), "bar.baz,foo");

        // redundant sub-path
        tree.add_field_path("foo.bar");
        assert_eq!(tree.to_string(), "bar.baz,foo");

        // new sub-path
        tree.add_field_path("bar.quz");
        assert_eq!(tree.to_string(), "bar.baz,bar.quz,foo");

        // path that matches several existing sub-paths
        tree.add_field_path("bar");
        assert_eq!(tree.to_string(), "bar,foo");
    }

    #[test]
    fn test_contains() {
        let mut tree = FieldMaskTree::default();

        assert!(!tree.contains("foo"));
        assert!(!tree.contains("foo.bar"));

        tree.add_field_path("foo.bar");

        assert!(tree.contains("foo"));
        assert!(tree.contains("foo.bar"));
        assert!(!tree.contains("foo.baz"));
        assert!(!tree.contains("foobar"));
    }

    #[test]
    fn test_map_keys() {
        // Empty tree → no wildcard, no keys
        let tree = FieldMaskTree::default();
        let keys: Option<Vec<&str>> = tree.map_keys().map(|it| it.collect());
        assert_eq!(keys, Some(vec![]));

        // Wildcard tree → None
        let tree = FieldMaskTree::new_wildcard();
        assert!(tree.map_keys().is_none());

        // Tree with specific keys
        let mut tree = FieldMaskTree::default();
        tree.add_field_path("key_a");
        tree.add_field_path("key_b");
        let mut keys: Vec<&str> = tree.map_keys().unwrap().collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["key_a", "key_b"]);

        // Subtree map_keys: after subtree(), map_keys on the result
        let mut tree = FieldMaskTree::default();
        tree.add_field_path("attributes.max_tx_gas");
        tree.add_field_path("attributes.max_num_events");

        // The subtree at "attributes" should have the two keys
        let subtree = tree.subtree("attributes").unwrap();
        let mut keys: Vec<&str> = subtree.map_keys().unwrap().collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["max_num_events", "max_tx_gas"]);

        // Subtree when "attributes" is a leaf (wildcard-like subtree) → None
        let mut tree = FieldMaskTree::default();
        tree.add_field_path("attributes");
        let subtree = tree.subtree("attributes").unwrap();
        assert!(subtree.map_keys().is_none());
    }

    #[test]
    fn test_map_field_filter() {
        // Simulates: wrapper "feature_flags" contains inner map field "flags"

        // Case 1: bare wrapper (wildcard) → None (empty map)
        let mut tree = FieldMaskTree::default();
        tree.add_field_path("feature_flags");
        let subtree = tree.subtree("feature_flags").unwrap();
        assert!(subtree.map_field_filter("flags").is_none());

        // Case 2: inner map field requested without keys → Some(None) (all entries)
        let mut tree = FieldMaskTree::default();
        tree.add_field_path("feature_flags.flags");
        let subtree = tree.subtree("feature_flags").unwrap();
        assert!(matches!(subtree.map_field_filter("flags"), Some(None)));

        // Case 3: specific keys → Some(Some(keys))
        let mut tree = FieldMaskTree::default();
        tree.add_field_path("feature_flags.flags.flag_a");
        tree.add_field_path("feature_flags.flags.flag_c");
        let subtree = tree.subtree("feature_flags").unwrap();
        let filter = subtree.map_field_filter("flags");
        let mut keys: Vec<String> = filter.unwrap().unwrap().into_iter().collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["flag_a", "flag_c"]);

        // Case 4: inner field name not in the tree → None (empty map)
        let mut tree = FieldMaskTree::default();
        tree.add_field_path("feature_flags.other_field");
        let subtree = tree.subtree("feature_flags").unwrap();
        assert!(subtree.map_field_filter("flags").is_none());
    }

    const EXC: &[&str] = &["json", "display"];

    #[test]
    fn explicit_only_leaf_survives_its_parent() {
        // "parent + explicit-only child" keeps both, in either insertion order.
        for order in [
            ["output_objects", "output_objects.json"],
            ["output_objects.json", "output_objects"],
        ] {
            let mut tree = FieldMaskTree::default();
            for path in order {
                tree.add_field_path_with_exceptions(path, EXC);
            }
            assert_eq!(tree.to_string(), "output_objects,output_objects.json");

            // The parent still selects its ordinary fields...
            assert!(tree.contains("output_objects.reference"));
            assert!(tree.contains("output_objects.bcs"));
            assert!(tree.contains("output_objects.json"));

            // ...and the gate sees the explicit-only child even though the node
            // is a wildcard (where `map_keys` reports no filter).
            let subtree = tree.subtree("output_objects").unwrap();
            let kids: Vec<&str> = subtree.explicit_children().collect();
            assert_eq!(kids, vec!["json"]);
            assert!(subtree.map_keys().is_none());
        }
    }

    #[test]
    fn non_exception_child_still_collapses_under_parent() {
        let mut tree = FieldMaskTree::default();
        tree.add_field_path_with_exceptions("output_objects", EXC);
        tree.add_field_path_with_exceptions("output_objects.bcs", EXC);
        // `bcs` is an ordinary field, subsumed by the wildcard parent.
        assert_eq!(tree.to_string(), "output_objects");
        let subtree = tree.subtree("output_objects").unwrap();
        assert!(subtree.explicit_children().next().is_none());
    }

    #[test]
    fn explicit_only_leaf_alone_excludes_siblings() {
        let mut tree = FieldMaskTree::default();
        tree.add_field_path_with_exceptions("output_objects.json", EXC);
        // Only `json` is selected; the parent is not a wildcard.
        assert!(tree.contains("output_objects.json"));
        assert!(!tree.contains("output_objects.reference"));
        let subtree = tree.subtree("output_objects").unwrap();
        let kids: Vec<&str> = subtree.explicit_children().collect();
        assert_eq!(kids, vec!["json"]);
    }

    #[test]
    fn explicit_only_leaf_survives_a_nested_parent() {
        // A bare grandparent plus a deeply-nested explicit-only leaf.
        let mut tree = FieldMaskTree::default();
        tree.add_field_path_with_exceptions("transactions", EXC);
        tree.add_field_path_with_exceptions("transactions.output_objects.json", EXC);
        assert_eq!(
            tree.to_string(),
            "transactions,transactions.output_objects.json"
        );
        assert!(tree.contains("transactions.digest"));

        let output_objects = tree
            .subtree("transactions")
            .unwrap()
            .subtree("output_objects")
            .unwrap();
        let kids: Vec<&str> = output_objects.explicit_children().collect();
        assert_eq!(kids, vec!["json"]);
    }

    #[test]
    fn without_exceptions_parent_subsumes_everything() {
        // The default path (no exceptions) keeps the standard collapse.
        let mut tree = FieldMaskTree::default();
        tree.add_field_path("output_objects");
        tree.add_field_path("output_objects.json");
        assert_eq!(tree.to_string(), "output_objects");
    }
}
