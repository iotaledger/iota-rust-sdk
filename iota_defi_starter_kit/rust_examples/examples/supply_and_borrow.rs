//! Example: Supply collateral and borrow assets
//!
//! This example demonstrates how to:
//! 1. Connect to an existing lending pool
//! 2. Supply collateral to the pool
//! 3. Borrow assets from the pool
//! 4. Monitor position health

use anyhow::{Context, Result};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    println!("🚀 Starting IOTA Move DeFi Starter Kit - Supply & Borrow Example");
    
    // 1. Configuration
    println!("⚙️  Loading configuration...");
    
    let config = DeFiConfig {
        network: Network::Testnet,
        pool_address: "0x1234567890abcdef".to_string(),
        asset_address: "0x2::sui::SUI".to_string(),
        wallet_path: "./wallet.json".to_string(),
    };
    
    println!("📊 Configuration:");
    println!("   Network: {:?}", config.network);
    println!("   Pool address: {}", config.pool_address);
    println!("   Asset: {}", config.asset_address);
    
    // 2. Connect to network and load wallet
    println!("🔗 Connecting to network...");
    
    // Simulate connection
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("✅ Connected to network");
    
    // 3. Check pool status
    println!("🏦 Checking pool status...");
    
    let pool_info = simulate_get_pool_info(&config.pool_address).await?;
    println!("📈 Pool information:");
    println!("   Total supply: {}", format_amount(pool_info.total_supply));
    println!("   Total borrowed: {}", format_amount(pool_info.total_borrowed));
    println!("   Utilization rate: {:.2}%", pool_info.utilization_rate as f64 / 10_000.0);
    println!("   Supply rate: {:.2}%", pool_info.supply_rate as f64 / 10_000.0);
    println!("   Borrow rate: {:.2}%", pool_info.borrow_rate as f64 / 10_000.0);
    
    // 4. Supply collateral
    println!("💰 Supplying collateral...");
    
    let supply_amount = 1_000_000_000; // 1 SUI (9 decimals)
    println!("   Amount: {}", format_amount(supply_amount));
    
    // Simulate supply transaction
    let supply_result = simulate_supply(&config.pool_address, supply_amount).await?;
    println!("✅ Collateral supplied successfully!");
    println!("   Transaction hash: {}", supply_result.tx_hash);
    
    // 5. Check user position
    println!("📊 Checking user position...");
    
    let user_position = simulate_get_user_position(&config.pool_address).await?;
    println!("👤 User position:");
    println!("   Supplied balance: {}", format_amount(user_position.supplied_balance));
    println!("   Borrowed balance: {}", format_amount(user_position.borrowed_balance));
    println!("   Health factor: {:.2}", user_position.health_factor as f64 / 1_000_000.0);
    println!("   Borrow limit: {}", format_amount(user_position.borrow_limit));
    
    // 6. Borrow assets
    println!("💸 Borrowing assets...");
    
    let borrow_amount = 500_000_000; // 0.5 SUI
    println!("   Amount: {}", format_amount(borrow_amount));
    println!("   Health factor before: {:.2}", user_position.health_factor as f64 / 1_000_000.0);
    
    // Check if borrowing is safe
    if user_position.health_factor < 1_200_000 {
        println!("⚠️  Warning: Health factor is low. Consider borrowing less.");
    }
    
    // Simulate borrow transaction
    let borrow_result = simulate_borrow(&config.pool_address, borrow_amount).await?;
    println!("✅ Assets borrowed successfully!");
    println!("   Transaction hash: {}", borrow_result.tx_hash);
    println!("   Borrow rate: {:.2}%", borrow_result.borrow_rate as f64 / 10_000.0);
    
    // 7. Check updated position
    println!("📈 Checking updated position...");
    
    let updated_position = simulate_get_user_position(&config.pool_address).await?;
    println!("👤 Updated position:");
    println!("   Supplied balance: {}", format_amount(updated_position.supplied_balance));
    println!("   Borrowed balance: {}", format_amount(updated_position.borrowed_balance));
    println!("   Health factor: {:.2}", updated_position.health_factor as f64 / 1_000_000.0);
    
    // 8. Risk assessment
    println!("⚠️  Risk assessment:");
    
    if updated_position.health_factor < 1_100_000 {
        println!("   ❌ High risk: Health factor below 1.1");
        println!("   💡 Recommendation: Add more collateral or repay some debt");
    } else if updated_position.health_factor < 1_500_000 {
        println!("   ⚠️  Medium risk: Health factor between 1.1 and 1.5");
        println!("   💡 Recommendation: Monitor position closely");
    } else {
        println!("   ✅ Low risk: Health factor above 1.5");
        println!("   💡 Recommendation: Position is safe");
    }
    
    // 9. Next steps
    println!();
    println!("🎉 Supply and borrow operations completed!");
    println!();
    println!("Next steps:");
    println!("1. Run flash_loan_exec example to test flash loans");
    println!("2. Monitor events with monitor_events example");
    println!("3. Consider repaying debt when health factor is low");
    
    Ok(())
}

// Helper functions
fn format_amount(amount: u64) -> String {
    format!("{:.9}", amount as f64 / 1_000_000_000.0)
}

// Simulation functions
async fn simulate_get_pool_info(pool_address: &str) -> Result<PoolInfo> {
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(PoolInfo {
        total_supply: 10_000_000_000,
        total_borrowed: 4_500_000_000,
        utilization_rate: 450_000, // 45%
        supply_rate: 35_000,       // 3.5%
        borrow_rate: 45_000,       // 4.5%
    })
}

async fn simulate_supply(pool_address: &str, amount: u64) -> Result<TransactionResult> {
    tokio::time::sleep(Duration::from_millis(800)).await;
    Ok(TransactionResult {
        tx_hash: "0xabcdef1234567890".to_string(),
        success: true,
    })
}

async fn simulate_borrow(pool_address: &str, amount: u64) -> Result<BorrowResult> {
    tokio::time::sleep(Duration::from_millis(800)).await;
    Ok(BorrowResult {
        tx_hash: "0xfedcba9876543210".to_string(),
        success: true,
        borrow_rate: 45_000,
    })
}

async fn simulate_get_user_position(pool_address: &str) -> Result<UserPosition> {
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(UserPosition {
        supplied_balance: 1_000_000_000,
        borrowed_balance: 500_000_000,
        health_factor: 2_000_000, // 2.0
        borrow_limit: 800_000_000,
    })
}

// Data structures
#[derive(Debug)]
enum Network {
    Testnet,
    Mainnet,
    Devnet,
}

struct DeFiConfig {
    network: Network,
    pool_address: String,
    asset_address: String,
    wallet_path: String,
}

struct PoolInfo {
    total_supply: u64,
    total_borrowed: u64,
    utilization_rate: u64,
    supply_rate: u64,
    borrow_rate: u64,
}

struct UserPosition {
    supplied_balance: u64,
    borrowed_balance: u64,
    health_factor: u64,
    borrow_limit: u64,
}

struct TransactionResult {
    tx_hash: String,
    success: bool,
}

struct BorrowResult {
    tx_hash: String,
    success: bool,
    borrow_rate: u64,
}