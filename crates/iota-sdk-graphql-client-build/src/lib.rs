// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::ops::Range;

/// Register the schema to enable building custom queries using cynic derive macros queries. Call
/// this function in a `build.rs` file in your crate if you need to build custom queries.
///
/// Examples
/// ```rust,ignore
/// // build.rs file
/// fn main() {
///     let schema_name = "MYSCHEMA"
///     iota_graphql_client_build::register_schema(schema_name);
/// }
///
/// // Cargo.toml
/// ...
/// [dependencies]
/// cynic = "3.8.0"
/// ...
/// [build-dependencies]
/// iota_graphql_client_build = "VERSION_HERE"
///
/// // lib.rs
/// // Custom query
/// use cynic::QueryBuilder;
/// use iota_graphql_client::{query_types::schema, GraphQLClient};
///
/// #[derive(cynic::QueryFragment, Debug)]
/// #[cynic(schema = "MYSCHEMA", graphql_type = "Query")]
/// pub struct MyQuery {
///    pub chain_identifier: String,
/// }
///
/// #[tokio::main]
/// async fn main() {
///     let client = GraphQLClient::new_mainnet().unwrap();
///     let operation = MyQuery::build(());
///     let q = client.run_query(&operation).await.unwrap();
///     println!("{:?}", q);
/// }
/// ```
pub fn register_schema(schema_name: &str) {
    let schema = include_str!("../schema.graphql");
    let schema = if cfg!(feature = "unstable") {
        schema.to_owned()
    } else {
        strip_unstable(schema, include_str!("../unstable.graphql"))
    };
    let sdl = merge_removed(&schema, include_str!("../removed.graphql"));
    cynic_codegen::register_schema(schema_name)
        .from_sdl(&sdl)
        .expect("Failed to find GraphQL Schema")
        .as_default()
        .unwrap();
}

/// Strips the definitions the node only serves on devnet from its schema, so that the generated
/// `query_types::schema` module only has them with the `unstable` feature.
///
/// The body of each `extend <kind> <Name> {` block in `unstable` is removed from the matching
/// definition in `schema`, and the members of each `extend union <Name> = A | B` line from the
/// matching union. Anything else in `unstable` is a definition, removed as is along with the blank
/// line after it.
fn strip_unstable(schema: &str, unstable: &str) -> String {
    let mut schema = schema.to_owned();
    let mut lines = unstable.lines();
    let mut definition = String::new();
    while let Some(line) = lines.next() {
        if definition.is_empty() && (line.is_empty() || line.starts_with('#')) {
            continue;
        }
        if let Some(header) = line.strip_prefix("extend union ") {
            let (name, members) = header
                .split_once(" = ")
                .unwrap_or_else(|| panic!("`{line}` must list members after ` = `"));
            for member in members.split(" | ") {
                remove_union_member(&mut schema, name, member);
            }
        } else if let Some(header) = line.strip_prefix("extend ") {
            let header = block_header(line, header);
            let body = block_body(&mut lines, line);
            let start = definition_body_start(&schema, header);
            let end = definition_body_end(&schema, start);
            remove_lines(&mut schema, start..end, &body)
                .unwrap_or_else(|| panic!("`{header}` must contain once:\n{body}"));
        } else {
            definition.push_str(line);
            definition.push('\n');
            if line == "}" || line.starts_with("union ") || line.starts_with("scalar ") {
                let len = schema.len();
                let position = remove_lines(&mut schema, 0..len, &definition)
                    .unwrap_or_else(|| panic!("the schema must define once:\n{definition}"));
                if schema[position..].starts_with('\n') {
                    schema.remove(position);
                }
                definition.clear();
            }
        }
    }
    assert!(
        definition.is_empty(),
        "the definition is never closed:\n{definition}"
    );
    schema
}

/// Removes `lines`, which must appear exactly once in `schema[range]` and start a line there.
/// Returns the offset they were removed at.
fn remove_lines(schema: &mut String, range: Range<usize>, lines: &str) -> Option<usize> {
    let mut matches = schema[range.clone()]
        .match_indices(lines)
        .map(|(offset, _)| range.start + offset)
        .filter(|&position| position == 0 || schema.as_bytes()[position - 1] == b'\n');
    let (Some(position), None) = (matches.next(), matches.next()) else {
        return None;
    };
    schema.replace_range(position..position + lines.len(), "");
    Some(position)
}

/// Removes `member` from the members of the `union <name> = A | B` line in `schema`.
fn remove_union_member(schema: &mut String, name: &str, member: &str) {
    let prefix = format!("union {name} = ");
    let (start, members) = schema
        .split_inclusive('\n')
        .scan(0, |offset, line| {
            let start = *offset;
            *offset += line.len();
            Some((start, line.trim_end()))
        })
        .find_map(|(start, line)| Some((start + prefix.len(), line.strip_prefix(&prefix)?)))
        .unwrap_or_else(|| panic!("`union {name}` is not defined in the schema"));
    let members = members.split(" | ").collect::<Vec<_>>();
    let kept = members
        .iter()
        .filter(|&&kept| kept != member)
        .copied()
        .collect::<Vec<_>>();
    assert!(
        kept.len() + 1 == members.len() && !kept.is_empty(),
        "`union {name}` must have `{member}` among other members"
    );
    let end = start + members.join(" | ").len();
    let kept = kept.join(" | ");
    schema.replace_range(start..end, &kept);
}

/// Merges the definitions the node removed back into its schema, so that the generated
/// `query_types::schema` module only loses items in a major release.
///
/// The body of each `extend <kind> <Name> {` block in `removed` is inserted at the top of the
/// matching definition in `schema`, as cynic ignores extensions. Anything else in `removed` is
/// appended as is.
fn merge_removed(schema: &str, removed: &str) -> String {
    let mut schema = schema.to_owned();
    let mut lines = removed.lines();
    while let Some(line) = lines.next() {
        let Some(header) = line.strip_prefix("extend ") else {
            schema.push('\n');
            schema.push_str(line);
            continue;
        };
        let header = block_header(line, header);
        let body = block_body(&mut lines, line);
        let position = definition_body_start(&schema, header);
        schema.insert_str(position, &body);
    }
    schema
}

/// Returns the `<kind> <Name>` of the `extend <kind> <Name> {` block opened by `line`, given the
/// `header` that follows `extend `.
fn block_header<'a>(line: &str, header: &'a str) -> &'a str {
    header
        .strip_suffix(" {")
        .unwrap_or_else(|| panic!("`{line}` must end with ` {{`"))
}

/// Returns the lines of the block opened by `line`, up to its closing `}`.
fn block_body<'a>(lines: &mut impl Iterator<Item = &'a str>, line: &str) -> String {
    let mut body = String::new();
    loop {
        match lines.next() {
            Some("}") => return body,
            Some(line) => {
                body.push_str(line);
                body.push('\n');
            }
            None => panic!("`{line}` is never closed"),
        }
    }
}

/// Returns the offset right after the line opening the `header` definition in `schema`, e.g.
/// `type Query {` or `type Object implements IObject & IOwner {` for `header` `type Query` or
/// `type Object`.
fn definition_body_start(schema: &str, header: &str) -> usize {
    let mut offset = 0;
    for line in schema.split_inclusive('\n') {
        offset += line.len();
        if line
            .trim_end()
            .strip_prefix(header)
            .is_some_and(|rest| rest.starts_with(' ') && rest.ends_with('{'))
        {
            return offset;
        }
    }
    panic!("`{header}` is not defined in the schema");
}

/// Returns the offset of the `}` line closing the definition whose body starts at `start`.
fn definition_body_end(schema: &str, start: usize) -> usize {
    let mut offset = start;
    for line in schema[start..].split_inclusive('\n') {
        if line.trim_end() == "}" {
            return offset;
        }
        offset += line.len();
    }
    panic!("the definition at offset {start} is never closed");
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "type Query {\n\ta: Int\n}\ntype QueryExt implements Node {\n\tb: Int\n}\nenum Kind {\n\tA\n}\n";

    #[test]
    fn extensions_are_merged_into_their_definition() {
        let removed = "extend type QueryExt {\n\tc: Int\n}\nextend type Query {\n\td: Int\n}\nextend enum Kind {\n\tB\n}\n";
        assert_eq!(
            merge_removed(SCHEMA, removed),
            "type Query {\n\td: Int\n\ta: Int\n}\ntype QueryExt implements Node {\n\tc: Int\n\tb: Int\n}\nenum Kind {\n\tB\n\tA\n}\n"
        );
    }

    #[test]
    fn other_definitions_are_appended() {
        let removed = "# comment\ntype Gone {\n\te: Int\n}";
        assert_eq!(
            merge_removed(SCHEMA, removed),
            format!("{SCHEMA}\n{removed}")
        );
    }

    #[test]
    #[should_panic(expected = "`type Missing` is not defined in the schema")]
    fn extending_an_unknown_definition_panics() {
        merge_removed(SCHEMA, "extend type Missing {\n\tf: Int\n}\n");
    }

    #[test]
    fn removed_definitions_merge_into_the_schema() {
        merge_removed(
            include_str!("../schema.graphql"),
            include_str!("../removed.graphql"),
        );
    }

    const UNSTABLE_SCHEMA: &str = "\"\"\"\nNew.\n\"\"\"\nunion New = A\n\ntype Query {\n\ta: Int\n\t\"\"\"\n\tNew.\n\t\"\"\"\n\tb: Int\n}\n\ntype A {\n\tc: Int\n}\n\nunion Kind = A | B | C\n";

    #[test]
    fn unstable_definitions_are_stripped() {
        let unstable = "# comment\n\n\"\"\"\nNew.\n\"\"\"\nunion New = A\n\ntype A {\n\tc: Int\n}\n\nextend union Kind = A | C\n\nextend type Query {\n\t\"\"\"\n\tNew.\n\t\"\"\"\n\tb: Int\n}\n";
        assert_eq!(
            strip_unstable(UNSTABLE_SCHEMA, unstable),
            "type Query {\n\ta: Int\n}\n\nunion Kind = B\n"
        );
    }

    #[test]
    #[should_panic(expected = "`union Kind` must have `D` among other members")]
    fn stripping_an_unknown_union_member_panics() {
        strip_unstable(UNSTABLE_SCHEMA, "extend union Kind = D\n");
    }

    #[test]
    #[should_panic(expected = "`type Query` must contain once")]
    fn stripping_an_unknown_field_panics() {
        strip_unstable(UNSTABLE_SCHEMA, "extend type Query {\n\tc: Int\n}\n");
    }

    #[test]
    #[should_panic(expected = "the schema must define once")]
    fn stripping_an_unknown_definition_panics() {
        strip_unstable(UNSTABLE_SCHEMA, "type B {\n\tc: Int\n}\n");
    }

    #[test]
    fn unstable_definitions_strip_from_the_schema() {
        let schema = strip_unstable(
            include_str!("../schema.graphql"),
            include_str!("../unstable.graphql"),
        );
        for name in [
            "AccountClaimKind",
            "ClaimAccountTransaction",
            "SmartAccountClaim",
            "CLAIM_ACCOUNT",
        ] {
            assert!(!schema.contains(name), "`{name}` is still in the schema");
        }
        merge_removed(&schema, include_str!("../removed.graphql"));
    }
}
