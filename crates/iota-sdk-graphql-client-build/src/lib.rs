// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

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
    let sdl = merge_removed(
        include_str!("../schema.graphql"),
        include_str!("../removed.graphql"),
    );
    cynic_codegen::register_schema(schema_name)
        .from_sdl(&sdl)
        .expect("Failed to find GraphQL Schema")
        .as_default()
        .unwrap();
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
        let header = header
            .strip_suffix(" {")
            .unwrap_or_else(|| panic!("`{line}` must end with ` {{`"));
        let mut body = String::new();
        loop {
            match lines.next() {
                Some("}") => break,
                Some(line) => {
                    body.push_str(line);
                    body.push('\n');
                }
                None => panic!("`{line}` is never closed"),
            }
        }
        let position = definition_body_start(&schema, header);
        schema.insert_str(position, &body);
    }
    schema
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
}
