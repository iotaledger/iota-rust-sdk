# Copyright (c) 2026 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# This example inspects a published Move package on testnet and prints its
# upgrade policy, version history, dependencies, functions, types, and sample
# objects.

from lib.iota_sdk import *

import asyncio
import json

FRAMEWORK_PACKAGE_ID = Address.framework().to_hex()
HEX_DIGITS = set("0123456789abcdefABCDEF")


async def main():
    package_id = "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d"
    package_address = Address.from_hex(package_id)
    client = GraphQlClient.new_testnet()

    # Fetch package metadata and version history.
    package = await client.package(package_address)
    if package is None:
        raise Exception("missing package")

    latest_package = await client.package_latest(package_address)
    if latest_package is None:
        raise Exception("missing latest package")

    versions = await fetch_package_versions(client, package_address)
    package_prefix = package.id().to_hex()
    print(
        f"Latest version: {latest_package.version().as_u64()} ({latest_package.id().to_hex()})"
    )
    # Resolve the current upgrade policy.
    print(
        f"Current package policy: {await current_package_policy(client, package.id())}"
    )
    print()

    # Print the package version history.
    print("Versions:")
    for version in versions:
        labels = []
        if version.id() == package.id():
            labels.append("requested")
        if version.id() == latest_package.id():
            labels.append("latest")

        line = f"- v{version.version().as_u64()} -> {version.id().to_hex()}"
        if len(labels) > 0:
            line += f" [{', '.join(labels)}]"
        print(line)
    print()

    # Print package dependencies and their linked versions.
    print("Dependencies:")
    linkage_table = package.linkage_table()
    if len(linkage_table) == 0:
        print("- none")
    else:
        for upgrade in sorted(linkage_table.values(),
                              key=lambda item: item.upgraded_id.to_hex()):
            print(
                f"- {upgrade.upgraded_id.to_hex()} @ v{upgrade.upgraded_version.as_u64()}"
            )
    print()

    # Inspect normalized modules, functions, types, and sample key objects.
    print("Package contents:")
    module_names = sorted(
        module_id.as_str() for module_id in package.modules().keys())

    for module_name in module_names:
        print(f"Module: {module_name}")

        module = await client.normalized_move_module(
            package_address,
            module_name,
            None,
            forward_page(),
            forward_page(),
            forward_page(),
            forward_page(),
        )
        if module is None:
            print("  metadata: missing")
            print()
            continue

        if module.functions is None or len(module.functions.nodes) == 0:
            print("  functions: none")
        else:
            print("  functions:")
            for function in module.functions.nodes:
                print(
                    f"    - {format_function_signature(str(function), package_prefix)}"
                )
            if module.functions.page_info.has_next_page:
                print("    - ...")

        if module.structs is None or len(module.structs.nodes) == 0:
            print("  types: none")
        else:
            print("  types:")
            for struct_ in module.structs.nodes:
                type_tag = f"{package_prefix}::{module_name}::{struct_.name}"
                print(f"    - {type_tag}")
                has_key_ability = (struct_.abilities is not None and
                                   MoveAbility.KEY in struct_.abilities)
                is_generic = (struct_.type_parameters is not None and
                              len(struct_.type_parameters) > 0)
                await print_object_samples(client, type_tag, has_key_ability,
                                           is_generic)
            if module.structs.page_info.has_next_page:
                print("    - ...")

        print()


def forward_page(cursor=None):
    return PaginationFilter(
        direction=Direction.FORWARD,
        cursor=cursor,
    )


def shorten_package_ids(signature):
    parts = []
    index = 0

    while index < len(signature):
        if signature.startswith("0x", index):
            end = index + 2
            while end < len(signature) and signature[end] in HEX_DIGITS:
                end += 1

            if end > index + 2:
                candidate = signature[index:end]
                try:
                    parts.append(Address.from_hex(candidate).to_short_hex())
                    index = end
                    continue
                except Exception:
                    parts.append(candidate)
                    index = end
                    continue

        parts.append(signature[index])
        index += 1

    return "".join(parts)


def format_function_signature(signature, package_prefix):
    return shorten_package_ids(signature.replace(f"{package_prefix}::", ""))


async def fetch_package_versions(client, package_address):
    versions = []
    cursor = None

    while True:
        page = await client.package_versions(
            package_address,
            pagination_filter=forward_page(cursor),
        )
        versions.extend(page.data)
        if page.page_info.has_next_page:
            cursor = page.page_info.end_cursor
        else:
            break

    versions.sort(key=lambda package: package.version().as_u64())
    return versions


async def print_object_samples(client, type_tag, has_key_ability, is_generic):
    if not has_key_ability:
        return

    if is_generic:
        print("    sample objects: skipped for generic type")
        return

    objects = await client.objects(
        ObjectFilter(type_tag=type_tag),
        PaginationFilter(direction=Direction.FORWARD, limit=3),
    )

    if len(objects.data) == 0:
        print("    sample objects: none found")
        return

    print("    sample objects:")
    for obj in objects.data:
        print(f"      - {obj.id().to_hex()} (version {obj.version().as_u64()})")
    if objects.page_info.has_next_page:
        print("      - ...")


def format_policy_name(policy):
    return {
        0: "Compatible",
        128: "Additive",
        192: "Dependency-only",
    }.get(policy, f"Unknown ({policy})")


def extract_policy(contents):
    try:
        policy = json.loads(contents).get("policy")
    except (TypeError, ValueError, json.JSONDecodeError):
        return None

    if isinstance(policy, str):
        return int(policy) if policy.isdigit() else None
    if isinstance(policy, int):
        return policy
    return None


async def resolve_upgrade_cap_id(client, package_id):
    page = await client.transactions_effects(
        TransactionsFilter().with_changed_object(package_id),
        PaginationFilter(direction=Direction.FORWARD, limit=1),
    )

    for effects in page.data:
        effects_v1 = effects.as_v1()
        for changed_obj in effects_v1.changed_objects():
            if not changed_obj.output_state.is_object_write():
                continue

            obj = await client.object(changed_obj.object_id,
                                      effects_v1.lamport_version())
            if obj is not None and obj.as_opt_struct() is not None:
                if obj.as_struct().struct_type == StructTag.new_upgrade_cap():
                    return changed_obj.object_id

    return None


def same_object_id(left, right):
    return isinstance(left, str) and left.casefold() == right.casefold()


def programmable_transaction_json(tx):
    tx_v1 = json.loads(tx.to_json()).get("1")
    if not isinstance(tx_v1, dict):
        return None

    kind = tx_v1.get("kind")
    if not isinstance(kind,
                      dict) or kind.get("kind") != "programmable_transaction":
        return None

    return kind


def is_package_make_immutable_call(command):
    return (isinstance(command, dict) and
            command.get("command") == "move_call" and
            same_object_id(command.get("package"), FRAMEWORK_PACKAGE_ID) and
            command.get("module") == "package" and
            command.get("function") == "make_immutable")


def input_matches_object_id(input_, object_id):
    return (isinstance(input_, dict) and input_.get("type")
            in {"immutable_or_owned", "receiving", "shared"} and
            same_object_id(input_.get("object_id"), object_id))


def publishes_package_as_immutable(tx):
    programmable_tx = programmable_transaction_json(tx)
    if programmable_tx is None:
        return False

    commands = programmable_tx.get("commands")
    if not isinstance(commands, list):
        return False

    publish_indexes = [
        index for index, command in enumerate(commands)
        if isinstance(command, dict) and command.get("command") == "publish"
    ]
    if len(publish_indexes) != 1:
        return False

    publish_index = publish_indexes[0]
    for command in commands[publish_index + 1:]:
        if not is_package_make_immutable_call(command):
            continue

        arguments = command.get("arguments")
        if (isinstance(arguments, list) and len(arguments) == 1 and
                arguments[0] == {
                    "result": publish_index
                }):
            return True

    return False


def uses_upgrade_cap_for_make_immutable(tx, upgrade_cap_id):
    programmable_tx = programmable_transaction_json(tx)
    if programmable_tx is None:
        return False

    inputs = programmable_tx.get("inputs")
    commands = programmable_tx.get("commands")
    if not isinstance(inputs, list) or not isinstance(commands, list):
        return False

    upgrade_cap_inputs = [
        index for index, input_ in enumerate(inputs)
        if input_matches_object_id(input_, upgrade_cap_id.to_hex())
    ]
    if len(upgrade_cap_inputs) == 0:
        return False

    for command in commands:
        if not is_package_make_immutable_call(command):
            continue

        arguments = command.get("arguments")
        if not isinstance(arguments, list) or len(arguments) != 1:
            continue

        argument = arguments[0]
        if (isinstance(argument, dict) and
                isinstance(argument.get("input"), int) and
                argument["input"] in upgrade_cap_inputs):
            return True

    return False


async def was_package_published_as_immutable(client, package_id):
    cursor = None

    while True:
        page = await client.transactions_data_effects(
            TransactionsFilter().with_changed_object(package_id),
            forward_page(cursor),
        )

        for tx_data in page.data:
            if publishes_package_as_immutable(
                    tx_data.signed_transaction.transaction):
                return True

        if page.page_info.has_next_page:
            cursor = page.page_info.end_cursor
        else:
            return False


async def was_upgrade_cap_used_for_make_immutable(client, upgrade_cap_id):
    cursor = None

    while True:
        page = await client.transactions_data_effects(
            TransactionsFilter().with_input_object(upgrade_cap_id),
            forward_page(cursor),
        )

        for tx_data in page.data:
            if uses_upgrade_cap_for_make_immutable(
                    tx_data.signed_transaction.transaction, upgrade_cap_id):
                return True

        if page.page_info.has_next_page:
            cursor = page.page_info.end_cursor
        else:
            return False


async def current_package_policy(client, package_id):
    upgrade_cap_id = await resolve_upgrade_cap_id(client, package_id)
    if upgrade_cap_id is None:
        if await was_package_published_as_immutable(client, package_id):
            return "Immutable"
        return "Unavailable"

    contents = await client.move_object_contents(upgrade_cap_id)
    if contents is None:
        if await was_upgrade_cap_used_for_make_immutable(
                client, upgrade_cap_id):
            return "Immutable"
        return "Unavailable"

    policy = extract_policy(contents)
    return format_policy_name(policy) if policy is not None else "Unavailable"


if __name__ == "__main__":
    asyncio.run(main())
