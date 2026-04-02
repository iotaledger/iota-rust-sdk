#!/usr/bin/env bash
set -euo pipefail

# This script is run from crates/iota-sdk-graphql-client/
readonly CLIENT_SCOPE="."
readonly FFI_SCOPE="../iota-sdk-ffi"
readonly EXAMPLES_SCOPE="../iota-sdk/examples"
readonly QUERY_TYPES_SCOPE="${CLIENT_SCOPE}/src/query_types"

echo "==> Checking GraphQL naming policy"

if [[ ! -d "${QUERY_TYPES_SCOPE}/move_schema" ]]; then
  echo "ERROR: expected domain-first folder \`${QUERY_TYPES_SCOPE}/move_schema\` to exist"
  exit 1
fi

if [[ -d "${QUERY_TYPES_SCOPE}/normalized_move" ]]; then
  echo "ERROR: legacy folder \`${QUERY_TYPES_SCOPE}/normalized_move\` must not exist"
  exit 1
fi

deny_hits="$(grep -rEn "normalized_move|move_normalized|NormalizedMove" \
  "${CLIENT_SCOPE}" "${FFI_SCOPE}" "${EXAMPLES_SCOPE}" \
  --exclude='*.sh' || true)"
if [[ -n "${deny_hits}" ]]; then
  echo "ERROR: deny-list identifiers found:"
  echo "${deny_hits}"
  exit 1
fi

required_tokens=(
  "move_schema"
  "MoveSchemaFunctionQuery"
  "MoveSchemaModuleQuery"
  "move_schema_function"
  "move_schema_module"
)

for token in "${required_tokens[@]}"; do
  if ! grep -rEq --exclude='*.sh' "${token}" "${CLIENT_SCOPE}" "${FFI_SCOPE}" "${EXAMPLES_SCOPE}"; then
    echo "ERROR: required token not found: ${token}"
    exit 1
  fi
done

echo "==> Checking root/non-root Query/Mutation suffix rules"
violations=0

while IFS= read -r file; do
  file_violations="$(
    awk -v file="${file}" '
      function get_graphql_type(attr, gtype, p) {
        gtype = ""
        p = attr
        if (match(p, /graphql_type[[:space:]]*=[[:space:]]*"[^"]+"/)) {
          gtype = substr(p, RSTART, RLENGTH)
          sub(/.*"/, "", gtype)
          sub(/".*/, "", gtype)
        }
        return gtype
      }

      BEGIN {
        in_attr = 0
        attr = ""
        pending = ""
      }

      /#\[cynic\(/ {
        in_attr = 1
        attr = $0
        next
      }

      {
        if (in_attr) {
          attr = attr "\n" $0
          if ($0 ~ /\)\]/) {
            in_attr = 0
            pending = attr
            attr = ""
          }
          next
        }

        if (pending != "" && $0 ~ /^[[:space:]]*pub struct[[:space:]]+[A-Za-z0-9_]+/) {
          name = $0
          sub(/^[[:space:]]*pub struct[[:space:]]+/, "", name)
          sub(/[[:space:]\{].*$/, "", name)
          gtype = get_graphql_type(pending)

          if (gtype == "Query" && name !~ /Query$/) {
            printf "%s:%d: root Query struct `%s` must end with `Query`\n", file, NR, name
            bad = 1
          }
          if (gtype == "Mutation" && name !~ /Mutation$/) {
            printf "%s:%d: root Mutation struct `%s` must end with `Mutation`\n", file, NR, name
            bad = 1
          }
          if (gtype != "Query" && gtype != "" && name ~ /Query$/) {
            printf "%s:%d: non-root struct `%s` must not use `*Query` (graphql_type=%s)\n", file, NR, name, gtype
            bad = 1
          }
          pending = ""
          next
        }

        if (pending != "" && $0 !~ /^[[:space:]]*$/ && $0 !~ /^[[:space:]]*#\[/ && $0 !~ /^[[:space:]]*\/\//) {
          pending = ""
        }
      }

      END {
        if (bad) {
          exit 1
        }
      }
    ' "${file}" || true
  )"

  if [[ -n "${file_violations}" ]]; then
    echo "${file_violations}"
    violations=1
  fi
done < <(find "${QUERY_TYPES_SCOPE}" -name '*.rs' -type f | sort)

if [[ "${violations}" -ne 0 ]]; then
  echo "ERROR: GraphQL naming policy violations detected"
  exit 1
fi

echo "GraphQL naming policy checks passed."
