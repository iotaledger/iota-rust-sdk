# Copyright (c) 2025 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

from lib.iota_sdk import *

import asyncio


async def main():
    client = GraphQlClient.new_localnet()

    private_key = Ed25519PrivateKey.random()
    owner = private_key.public_key().derive_address()

    faucet = FaucetClient.new_localnet()
    await faucet.request_and_wait_for_finalized(owner, client)

    # Stake to get a StakedIota object that can be unstaked
    validators = await client.active_validators()
    if len(validators.data) == 0:
        raise Exception("no validators found")
    stake_builder = client.transaction_builder(owner)
    stake_builder.stake(PtbArgument.u64(1000000000), validators.data[0].address)
    stake_tx = await stake_builder.finish()
    sig = private_key.sign_transaction(stake_tx)
    await client.execute_transaction([sig], stake_tx,
                                     WaitForTransaction.FINALIZED)

    # Unstake
    staked_iotas = await client.objects(filter=ObjectFilter(
        type_tag=str(StructTag.new_staked_iota()), owner=owner))
    if len(staked_iotas.data) == 0:
        raise Exception("no staked iotas found")
    staked_iota = staked_iotas.data[0]

    builder = client.transaction_builder(staked_iota.owner().as_address())

    builder.unstake(PtbArgument.object_id(staked_iota.id()))

    res = await builder.dry_run()
    if res.error is not None:
        raise Exception("Failed to unstake:", res.error)

    print("Unstake dry run was successful!")


if __name__ == "__main__":
    asyncio.run(main())
