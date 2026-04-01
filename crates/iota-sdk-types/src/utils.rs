// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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
