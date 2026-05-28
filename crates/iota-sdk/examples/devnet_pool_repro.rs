// Reproducer for the "error decoding response body" doctest failures against
// devnet. Runs N sequential builder transactions (same pattern as the
// transaction-builder doctests) through ONE Client; reqwest's keepalive pool
// reuses connections that devnet's load balancer drops after a few hits, and
// the next `.json()` decode fails with:
//
//   error decoding response body
//   caused by: expected value at line 1 column 1
//
//   cargo run --example devnet_pool_repro

use std::str::FromStr;

use iota_sdk::{
    graphql_client::Client,
    transaction_builder::TransactionBuilder,
    types::{Address, ObjectId},
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    let client = Client::new_devnet();
    println!("endpoint: https://graphql.devnet.iota.cafe");

    let sender =
        Address::from_str("0x2214d627c48154536a168ed89fddaf7a87e509c2d3b853737555168526acd8ab")?;
    let coin = ObjectId::from_str(
        "0x5d34525da0712d713c9ea8872cf04976948312eb603990ba860a55c1b5652280",
    )?;
    let to = Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    const N: usize = 20;
    for i in 1..=N {
        let mut b = TransactionBuilder::new(sender).with_client(&client);
        b.send_coins([coin], to, 100u64);
        match b.finish().await {
            Ok(_) => println!("[{i:02}/{N}] ok"),
            Err(e) => {
                println!("[{i:02}/{N}] FAILED: {e:?}");
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
