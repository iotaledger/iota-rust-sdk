// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Trait for types that render as tree sub-trees.
///
/// Types implementing this trait can render their fields as a tree structure
/// with box-drawing characters (`├──`, `└──`, `│`).
///
/// Each `fmt_tree` impl must call [`TreeWriter::header`] before any other
/// writer method, on every arm of an enum dispatch. [`TreeWriter::child`] and
/// [`TreeWriter::inline_child`] leave state behind for the child's `header`
/// call to consume; writing a leaf or branch first leaves it pending and
/// applies it to some later, unrelated node. An impl that only delegates
/// (`Self::V1(v1) => v1.fmt_tree(w)`) satisfies this through the type it
/// delegates to.
///
/// Use [`impl_tree_display`] to generate the `Display` impl.
pub(crate) trait TreeDisplay {
    fn fmt_tree(&self, w: &mut TreeWriter<'_, '_>) -> std::fmt::Result;
}

/// Generates `Display` impls that delegate to [`TreeDisplay::fmt_tree`].
macro_rules! impl_tree_display {
    ($($ty:ty),* $(,)?) => {
        $(
        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut w = crate::TreeWriter::new(f);
                crate::TreeDisplay::fmt_tree(self, &mut w)
            }
        }
        )*
    };
}
pub(crate) use impl_tree_display;

/// A label a parent has written, waiting for its child's header.
enum PendingLabel {
    /// A field name, which already says what the node is.
    Named(String),
    /// An index, which names nothing.
    Indexed,
}

/// A tree node writer that tracks depth and sibling position for rendering
/// tree-structured output with box-drawing characters.
pub(crate) struct TreeWriter<'f, 'a> {
    f: &'f mut std::fmt::Formatter<'a>,
    prefix: String,
    needs_newline: bool,
    inline_label: Option<PendingLabel>,
    pending_enum: Option<String>,
    skip_header: bool,
}

impl<'f, 'a> TreeWriter<'f, 'a> {
    pub fn new(f: &'f mut std::fmt::Formatter<'a>) -> Self {
        Self {
            f,
            prefix: String::new(),
            needs_newline: false,
            inline_label: None,
            pending_enum: None,
            skip_header: false,
        }
    }

    /// Write the root label without connectors. When called as a child
    /// (via [`child`](Self::child)), the parent already wrote the field
    /// label, so the header is appended to it as `Label: Header` (or
    /// omitted when it repeats the label).
    pub fn header(&mut self, text: &str) -> std::fmt::Result {
        let enum_name = self.pending_enum.take();
        if std::mem::take(&mut self.skip_header) {
            return Ok(());
        }
        if let Some(pending) = self.inline_label.take() {
            match pending {
                // The label already names the type; printing it twice adds nothing.
                PendingLabel::Named(label) if label == text => {}
                // A field label names the node, so the enum name is dropped.
                PendingLabel::Named(_) => write!(self.f, ": {text}")?,
                PendingLabel::Indexed => match &enum_name {
                    Some(name) => write!(self.f, ": {name}: {text}")?,
                    None => write!(self.f, ": {text}")?,
                },
            }
            return Ok(());
        }
        if self.needs_newline {
            writeln!(self.f)?;
        }
        match &enum_name {
            Some(name) => write!(self.f, "{}{name}: {text}", self.prefix)?,
            None => write!(self.f, "{}{}", self.prefix, text)?,
        }
        self.needs_newline = true;
        Ok(())
    }

    /// Name the enum whose variant is about to write its header, so the node
    /// reads `Enum Name: Variant`.
    ///
    /// The name is dropped where a field label already says what the node is,
    /// and kept at a root or under an index, which name nothing. Nested enums
    /// each add their name, so a variant holding another enum reads as the
    /// whole chain down to the type that writes the header.
    pub fn enum_name(&mut self, name: &str) {
        match &mut self.pending_enum {
            Some(pending) => {
                pending.push_str(": ");
                pending.push_str(name);
            }
            None => self.pending_enum = Some(name.to_owned()),
        }
    }

    fn write_connector(&mut self, is_last: bool) -> std::fmt::Result {
        if self.needs_newline {
            writeln!(self.f)?;
        }
        let connector = if is_last { "└── " } else { "├── " };
        write!(self.f, "{}{}", self.prefix, connector)?;
        self.needs_newline = true;
        Ok(())
    }

    /// Write a leaf node: `├── Label: value` or `└── Label: value`.
    ///
    /// A multi-line value keeps the tree readable: it starts on its own line
    /// below the label, with all its lines indented equally.
    pub fn leaf(
        &mut self,
        label: &str,
        value: &dyn std::fmt::Display,
        is_last: bool,
    ) -> std::fmt::Result {
        self.write_connector(is_last)?;
        let value = value.to_string();
        if value.contains('\n') {
            write!(self.f, "{label}:")?;
            let extension = if is_last { "    " } else { "│   " };
            for line in value.lines() {
                write!(self.f, "\n{}{extension}{line}", self.prefix)?;
            }
            Ok(())
        } else {
            write!(self.f, "{label}: {value}")
        }
    }

    /// Write a branch with children rendered by a closure.
    pub fn branch(
        &mut self,
        label: &str,
        is_last: bool,
        children: impl FnOnce(&mut Self) -> std::fmt::Result,
    ) -> std::fmt::Result {
        self.write_connector(is_last)?;
        write!(self.f, "{label}")?;
        let extension = if is_last { "    " } else { "│   " };
        let old_len = self.prefix.len();
        self.prefix.push_str(extension);
        children(self)?;
        self.prefix.truncate(old_len);
        Ok(())
    }

    /// Write a [`TreeDisplay`] child as a sub-tree.
    pub fn child(
        &mut self,
        label: &str,
        child: &dyn TreeDisplay,
        is_last: bool,
    ) -> std::fmt::Result {
        self.branch(label, is_last, |w| {
            w.inline_label = Some(PendingLabel::Named(label.to_string()));
            child.fmt_tree(w)
        })
    }

    /// Write a [`TreeDisplay`] child under its index, which names nothing, so a
    /// variant header keeps its enum name.
    fn indexed_child(
        &mut self,
        index: usize,
        child: &dyn TreeDisplay,
        is_last: bool,
    ) -> std::fmt::Result {
        self.branch(&index.to_string(), is_last, |w| {
            w.inline_label = Some(PendingLabel::Indexed);
            child.fmt_tree(w)
        })
    }

    /// Render a [`TreeDisplay`] child's fields under the header just written,
    /// dropping the child's own header and nesting level.
    pub fn inline_child(&mut self, child: &dyn TreeDisplay) -> std::fmt::Result {
        self.skip_header = true;
        child.fmt_tree(self)
    }

    /// Display a collection of `Display` items as indexed leaf nodes.
    pub fn leaves<I>(&mut self, label: &str, items: I, is_last: bool) -> std::fmt::Result
    where
        I: IntoIterator,
        I::Item: std::fmt::Display,
        I::IntoIter: ExactSizeIterator,
    {
        let items = items.into_iter();
        if items.len() == 0 {
            self.leaf(label, &"[]", is_last)
        } else {
            self.branch(label, is_last, |w| {
                let last_idx = items.len() - 1;
                for (i, item) in items.enumerate() {
                    w.leaf(&i.to_string(), &item, i == last_idx)?;
                }
                Ok(())
            })
        }
    }

    /// Display a slice of [`TreeDisplay`] items as indexed sub-trees.
    pub fn children(
        &mut self,
        label: &str,
        items: &[impl TreeDisplay],
        is_last: bool,
    ) -> std::fmt::Result {
        if items.is_empty() {
            self.leaf(label, &"[]", is_last)
        } else {
            self.branch(label, is_last, |w| {
                let last_idx = items.len() - 1;
                for (i, item) in items.iter().enumerate() {
                    w.indexed_child(i, item, i == last_idx)?;
                }
                Ok(())
            })
        }
    }

    /// Display an `Option<impl Display>`, showing "None" for `None`.
    pub fn option_leaf(
        &mut self,
        label: &str,
        opt: &Option<impl std::fmt::Display>,
        is_last: bool,
    ) -> std::fmt::Result {
        match opt {
            Some(v) => self.leaf(label, v, is_last),
            None => self.leaf(label, &"None", is_last),
        }
    }

    /// Display an `Option<impl TreeDisplay>` as a sub-tree, showing "None" for
    /// `None`.
    pub fn option_child(
        &mut self,
        label: &str,
        opt: &Option<impl TreeDisplay>,
        is_last: bool,
    ) -> std::fmt::Result {
        match opt {
            Some(v) => self.child(label, v, is_last),
            None => self.leaf(label, &"None", is_last),
        }
    }

    /// Display a `Vec<Vec<u8>>` as Base64-encoded indexed leaves.
    pub fn base64_leaves(
        &mut self,
        label: &str,
        items: &[Vec<u8>],
        is_last: bool,
    ) -> std::fmt::Result {
        if items.is_empty() {
            self.leaf(label, &"[]", is_last)
        } else {
            use base64ct::Encoding;
            self.branch(label, is_last, |w| {
                let last_idx = items.len() - 1;
                for (i, bytes) in items.iter().enumerate() {
                    w.leaf(
                        &i.to_string(),
                        &base64ct::Base64::encode_string(bytes),
                        i == last_idx,
                    )?;
                }
                Ok(())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    /// Helper that captures formatted output by implementing Display with a
    /// closure.
    struct FmtFn<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result>(F);

    impl<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result> fmt::Display for FmtFn<F> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            (self.0)(f)
        }
    }

    #[test]
    fn writer_starts_without_a_leading_newline() {
        let output = FmtFn(|f| {
            let mut w = TreeWriter::new(f);
            w.leaf("Key", &"value", true)
        })
        .to_string();

        assert_eq!(output, "└── Key: value");
    }

    /// Renders the output a closure writes into a fresh [`TreeWriter`].
    fn render(body: impl Fn(&mut TreeWriter<'_, '_>) -> fmt::Result) -> String {
        FmtFn(move |f| body(&mut TreeWriter::new(f))).to_string()
    }

    /// Minimal [`TreeDisplay`] type for exercising sub-tree rendering.
    struct Point {
        x: u8,
        y: u8,
    }

    impl TreeDisplay for Point {
        fn fmt_tree(&self, w: &mut TreeWriter<'_, '_>) -> fmt::Result {
            w.header("Point")?;
            w.leaf("X", &self.x, false)?;
            w.leaf("Y", &self.y, true)
        }
    }

    impl_tree_display!(Point);

    #[test]
    fn header_writes_root_label_without_connector() {
        assert_eq!(render(|w| w.header("Root")), "Root");

        let expected = "
Root
└── Key: value";
        assert_eq!(
            render(|w| {
                w.header("Root")?;
                w.leaf("Key", &"value", true)
            }),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn leaf_connector_depends_on_sibling_position() {
        let expected = "
├── First: 1
└── Last: 2";
        assert_eq!(
            render(|w| {
                w.leaf("First", &1, false)?;
                w.leaf("Last", &2, true)
            }),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn leaf_indents_multi_line_value_below_its_label() {
        let expected = "
└── Label:
    line1
    line2";
        assert_eq!(
            render(|w| w.leaf("Label", &"line1\nline2", true)),
            expected.strip_prefix('\n').unwrap()
        );

        let expected = "
├── Label:
│   line1
│   line2
└── Last: x";
        assert_eq!(
            render(|w| {
                w.leaf("Label", &"line1\nline2", false)?;
                w.leaf("Last", &"x", true)
            }),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn branch_extends_prefix_for_children() {
        let expected = "
└── Parent
    └── Child: v";
        assert_eq!(
            render(|w| w.branch("Parent", true, |w| w.leaf("Child", &"v", true))),
            expected.strip_prefix('\n').unwrap()
        );

        let expected = "
├── Parent
│   └── Child: v
└── Last: x";
        assert_eq!(
            render(|w| {
                w.branch("Parent", false, |w| w.leaf("Child", &"v", true))?;
                w.leaf("Last", &"x", true)
            }),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn child_appends_header_to_the_label_line() {
        let expected = "
└── Origin: Point
    ├── X: 1
    └── Y: 2";
        assert_eq!(
            render(|w| w.child("Origin", &Point { x: 1, y: 2 }, true)),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn child_omits_header_equal_to_the_label() {
        let expected = "
└── Point
    ├── X: 1
    └── Y: 2";
        assert_eq!(
            render(|w| w.child("Point", &Point { x: 1, y: 2 }, true)),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn inline_child_renders_fields_without_a_level() {
        let expected = "
Origin
├── X: 1
└── Y: 2";
        assert_eq!(
            render(|w| {
                w.header("Origin")?;
                w.inline_child(&Point { x: 1, y: 2 })
            }),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn leaves_writes_one_node_per_item() {
        let empty: &[u8] = &[];
        assert_eq!(render(|w| w.leaves("Items", empty, true)), "└── Items: []");
        let expected = "
└── Items
    ├── 0: 10
    └── 1: 20";
        assert_eq!(
            render(|w| w.leaves("Items", [10, 20], true)),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn leaves_accepts_any_collection() {
        let set = std::collections::BTreeSet::from([20, 10]);
        assert_eq!(
            render(|w| w.leaves("Items", std::collections::BTreeSet::<u8>::new(), true)),
            "└── Items: []"
        );
        let expected = "
└── Items
    ├── 0: 10
    └── 1: 20";
        assert_eq!(
            render(|w| w.leaves("Items", &set, true)),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn children_renders_indexed_sub_trees() {
        let empty: &[Point] = &[];
        assert_eq!(
            render(|w| w.children("Points", empty, true)),
            "└── Points: []"
        );
        let expected = "
└── Points
    └── 0: Point
        ├── X: 1
        └── Y: 2";
        assert_eq!(
            render(|w| w.children("Points", &[Point { x: 1, y: 2 }], true)),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn option_leaf_renders_value_or_none() {
        assert_eq!(
            render(|w| w.option_leaf("Opt", &Some(5), true)),
            "└── Opt: 5"
        );
        assert_eq!(
            render(|w| w.option_leaf("Opt", &None::<u8>, true)),
            "└── Opt: None"
        );
    }

    #[test]
    fn option_child_renders_sub_tree_or_none() {
        let expected = "
└── Origin: Point
    ├── X: 1
    └── Y: 2";
        assert_eq!(
            render(|w| w.option_child("Origin", &Some(Point { x: 1, y: 2 }), true)),
            expected.strip_prefix('\n').unwrap()
        );
        assert_eq!(
            render(|w| w.option_child("Origin", &None::<Point>, true)),
            "└── Origin: None"
        );
    }

    #[test]
    fn base64_leaves_encodes_each_entry() {
        assert_eq!(
            render(|w| w.base64_leaves("Data", &[], true)),
            "└── Data: []"
        );
        let expected = "
└── Data
    └── 0: AQID";
        assert_eq!(
            render(|w| w.base64_leaves("Data", &[vec![1, 2, 3]], true)),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn impl_tree_display_generates_display_from_fmt_tree() {
        let expected = "
Point
├── X: 1
└── Y: 2";
        assert_eq!(
            Point { x: 1, y: 2 }.to_string(),
            expected.strip_prefix('\n').unwrap()
        );
    }

    fn sample_transaction() -> crate::Transaction {
        use crate::transaction::*;

        Transaction::V1(TransactionV1 {
            kind: TransactionKind::Programmable(ProgrammableTransaction {
                inputs: vec![Input::Pure(vec![1, 2, 3])],
                commands: vec![Command::SplitCoins(SplitCoins {
                    coin: Argument::Gas,
                    amounts: vec![Argument::Input(0)],
                })],
            }),
            sender: crate::Address::ZERO,
            gas_payment: GasPayment {
                objects: vec![crate::ObjectReference::new(
                    crate::ObjectId::ZERO,
                    crate::Version::from_u64(42),
                    crate::ObjectDigest::ZERO,
                )],
                owner: crate::Address::ZERO,
                price: 1000,
                budget: 5_000_000,
            },
            expiration: TransactionExpiration::None,
        })
    }

    #[test]
    fn transaction_renders_as_nested_tree() {
        let expected = "
Transaction: Transaction V1
├── Kind: Programmable Transaction
│   ├── Inputs
│   │   └── 0: Input: Pure
│   │       └── Value: 010203
│   └── Commands
│       └── 0: Command: Split Coins
│           ├── Coin: Gas
│           └── Amounts
│               └── 0: Input(0)
├── Sender: 0x0000000000000000000000000000000000000000000000000000000000000000
├── Gas Payment
│   ├── Objects
│   │   └── 0: Object Reference
│   │       ├── Object ID: 0x0000000000000000000000000000000000000000000000000000000000000000
│   │       ├── Version: 42
│   │       └── Digest: 11111111111111111111111111111111
│   ├── Owner: 0x0000000000000000000000000000000000000000000000000000000000000000
│   ├── Price: 1000
│   └── Budget: 5000000
└── Expiration: None";

        assert_eq!(
            sample_transaction().to_string(),
            expected.strip_prefix('\n').unwrap()
        );
    }

    #[test]
    fn tree_typed_field_renders_as_indented_sub_tree() {
        use crate::crypto::{
            Ed25519PublicKey, Ed25519Signature, MultisigAggregatedSignature, MultisigCommittee,
            MultisigMember, MultisigMemberSignature,
        };

        let committee = MultisigCommittee::new_unchecked(
            vec![MultisigMember::new(Ed25519PublicKey::new([0; 32]), 1)],
            1,
        );
        let signature = MultisigAggregatedSignature::new_unchecked(
            vec![MultisigMemberSignature::Ed25519(Ed25519Signature::new(
                [0; 64],
            ))],
            1,
            committee,
        );

        let expected = "
Multisig Aggregated Signature
├── Committee: Multisig Committee
│   ├── Members
│   │   └── 0: Multisig Member
│   │       ├── Public Key: Ed25519PublicKey(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=)
│   │       └── Weight: 1
│   └── Threshold: 1
├── Signatures
│   └── 0: Multisig Member Signature: Ed25519Signature(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==)
└── Bitmap: 1";

        assert_eq!(signature.to_string(), expected.strip_prefix('\n').unwrap());
    }

    #[test]
    fn multi_line_leaf_value_is_indented_under_its_label() {
        use crate::crypto::{Intent, IntentAppId, IntentMessage, IntentScope, IntentVersion};

        let message = IntentMessage::new(
            Intent::new(
                IntentScope::TransactionData,
                IntentVersion::V0,
                IntentAppId::Iota,
            ),
            sample_transaction(),
        );

        let expected = "
Intent Message
├── Intent
│   ├── Scope: TransactionData
│   ├── Version: V0
│   └── App ID: Iota
└── Value:
    Transaction: Transaction V1
    ├── Kind: Programmable Transaction
    │   ├── Inputs
    │   │   └── 0: Input: Pure
    │   │       └── Value: 010203
    │   └── Commands
    │       └── 0: Command: Split Coins
    │           ├── Coin: Gas
    │           └── Amounts
    │               └── 0: Input(0)
    ├── Sender: 0x0000000000000000000000000000000000000000000000000000000000000000
    ├── Gas Payment
    │   ├── Objects
    │   │   └── 0: Object Reference
    │   │       ├── Object ID: 0x0000000000000000000000000000000000000000000000000000000000000000
    │   │       ├── Version: 42
    │   │       └── Digest: 11111111111111111111111111111111
    │   ├── Owner: 0x0000000000000000000000000000000000000000000000000000000000000000
    │   ├── Price: 1000
    │   └── Budget: 5000000
    └── Expiration: None";

        assert_eq!(message.to_string(), expected.strip_prefix('\n').unwrap());
    }
}
