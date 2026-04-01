// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Write an iterator of items to a formatter, joined by a separator.
///
/// If `delimiters` is provided, the output is wrapped in the given left and
/// right delimiter strings. An empty iterator produces no output at all (not
/// even delimiters).
///
/// # Examples
///
/// ```
/// use std::fmt;
///
/// struct Nums(Vec<i32>);
///
/// impl fmt::Display for Nums {
///     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
///         iota_sdk_types::utils::write_sep(f, &self.0, Some(("[", "]")), ", ")
///     }
/// }
///
/// assert_eq!(Nums(vec![1, 2, 3]).to_string(), "[1, 2, 3]");
/// assert_eq!(Nums(vec![]).to_string(), "");
/// ```
pub fn write_sep<T: core::fmt::Display>(
    f: &mut core::fmt::Formatter<'_>,
    items: impl IntoIterator<Item = T>,
    delimiters: Option<(&str, &str)>,
    separator: &str,
) -> std::fmt::Result {
    let mut xs = items.into_iter();
    let Some(x) = xs.next() else {
        return Ok(());
    };
    if let Some((l, _)) = delimiters {
        write!(f, "{l}")?;
    }
    write!(f, "{x}")?;
    for x in xs {
        write!(f, "{separator}{x}")?;
    }
    if let Some((_, r)) = delimiters {
        write!(f, "{r}")?;
    }
    Ok(())
}
