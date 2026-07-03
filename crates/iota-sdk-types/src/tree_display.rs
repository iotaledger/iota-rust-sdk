// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Trait for types that render as tree sub-trees.
///
/// Types implementing this trait can render their fields as a tree structure
/// with box-drawing characters (`├──`, `└──`, `│`).
///
/// Each `fmt_tree` impl should start with `w.header("TypeName")` to define
/// the root label. Use [`impl_tree_display`] to generate the `Display` impl.
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

/// A tree node writer that tracks depth and sibling position for rendering
/// tree-structured output with box-drawing characters.
pub(crate) struct TreeWriter<'f, 'a> {
    f: &'f mut std::fmt::Formatter<'a>,
    prefix: String,
    needs_newline: bool,
    skip_header: bool,
}

impl<'f, 'a> TreeWriter<'f, 'a> {
    pub fn new(f: &'f mut std::fmt::Formatter<'a>) -> Self {
        Self {
            f,
            prefix: String::new(),
            needs_newline: false,
            skip_header: false,
        }
    }

    /// Write the root label without connectors. When called as a child
    /// (via [`child`](Self::child)), this is a no-op because the parent
    /// already wrote the label.
    pub fn header(&mut self, text: &str) -> std::fmt::Result {
        if self.skip_header {
            self.skip_header = false;
            return Ok(());
        }
        if self.needs_newline {
            writeln!(self.f)?;
        }
        write!(self.f, "{}{}", self.prefix, text)?;
        self.needs_newline = true;
        Ok(())
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

    /// Write a leaf node: `├── Label: value` or `└── Label: value`
    pub fn leaf(
        &mut self,
        label: &str,
        value: &dyn std::fmt::Display,
        is_last: bool,
    ) -> std::fmt::Result {
        self.write_connector(is_last)?;
        write!(self.f, "{label}: {value}")
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
            w.skip_header = true;
            child.fmt_tree(w)
        })
    }

    /// Display a `Vec` of `Display` items as indexed leaf nodes.
    pub fn vec_inline(
        &mut self,
        label: &str,
        items: &[impl std::fmt::Display],
        is_last: bool,
    ) -> std::fmt::Result {
        if items.is_empty() {
            self.leaf(label, &"[]", is_last)
        } else {
            self.branch(label, is_last, |w| {
                let last_idx = items.len() - 1;
                for (i, item) in items.iter().enumerate() {
                    w.leaf(&i.to_string(), &item, i == last_idx)?;
                }
                Ok(())
            })
        }
    }

    /// Display a `Vec` of [`TreeDisplay`] items as indexed sub-trees.
    pub fn vec_children(
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
                    w.child(&i.to_string(), item, i == last_idx)?;
                }
                Ok(())
            })
        }
    }

    /// Display an `Option<impl Display>`, showing "None" for `None`.
    pub fn option(
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
    pub fn bytes_vec(&mut self, label: &str, items: &[Vec<u8>], is_last: bool) -> std::fmt::Result {
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
    struct AfterText<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result>(F);

    impl<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result> fmt::Display for AfterText<F> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            (self.0)(f)
        }
    }

    #[test]
    fn new_without_after_text_has_no_leading_newline() {
        let output = AfterText(|f| {
            let mut w = TreeWriter::new(f);
            w.leaf("Key", &"value", true)
        })
        .to_string();

        assert_eq!(output, "└── Key: value");
    }
}
