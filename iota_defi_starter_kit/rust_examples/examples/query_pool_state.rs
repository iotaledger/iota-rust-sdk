//! Example: Query pool state and user positions
//!
//! This example demonstrates how to:
//! 1. Query various DeFi pool states
//! 2. Monitor user positions and health factors
//! 3. Analyze risk metrics
//! 4. Generate reports and alerts

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    println!("🚀 Starting IOTA Move DeFi Starter Kit - Query Pool State Example");
    println!("📊 Real-time monitoring and analytics for DeFi pools");
    
    // 1. Configuration
    println!("⚙️  Loading monitoring configuration...");
    
    let config = MonitorConfig {
        network: Network::Testnet,
        pools: vec![
            PoolConfig {
                address: "0x1234567890abcdef".to_string(),
                name: "Main Lending Pool".to_string(),
                asset: "SUI".to_string(),
            },
            PoolConfig {
                address: "0xfedcba9876543210".to_string(),
                name: "Flash Loan Pool".to_string(),
                asset: "SUI".to_string(),
            },
            PoolConfig {
                address: "0xabcdef1234567890".to_string(),
                name: "USDC Lending Pool".to_string(),
                asset: "USDC".to_string(),
            },
        ],
        refresh_interval: Duration::from_secs(30),
        alert_thresholds: AlertThresholds {
            min_health_factor: 1_100_000, // 1.1
            max_utilization: 850_000,     // 85%
            min_liquidity: 1_000_000_000, // 1 SUI
        },
    };
    
    println!("📋 Monitoring {} pools", config.pools.len());
    for (i, pool) in config.pools.iter().enumerate() {
        println!("   {}. {} ({}) - {}", i + 1, pool.name, pool.asset, pool.address);
    }
    
    // 2. Initial data collection
    println!("📡 Collecting initial pool data...");
    
    let mut pool_states = HashMap::new();
    let mut alerts = Vec::new();
    
    for pool in &config.pools {
        println!("   Querying {}...", pool.name);
        
        let state = simulate_query_pool_state(&pool.address).await?;
        pool_states.insert(pool.address.clone(), state.clone());
        
        // Check for alerts
        let pool_alerts = check_pool_alerts(&pool, &state, &config.alert_thresholds);
        alerts.extend(pool_alerts);
        
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    
    // 3. Display pool status dashboard
    println!();
    println!("📈 DeFi Pool Status Dashboard");
    println!("{}", "-".repeat(80));
    
    for pool in &config.pools {
        if let Some(state) = pool_states.get(&pool.address) {
            print_pool_status(pool, state);
        }
    }
    
    // 4. User positions analysis
    println!();
    println!("👤 User Positions Analysis");
    println!("{}", "-".repeat(80));
    
    let user_positions = simulate_get_user_positions().await?;
    
    println!("   Total users: {}", user_positions.len());
    
    // Analyze risk distribution
    let mut healthy_positions = 0;
    let mut warning_positions = 0;
    let mut risky_positions = 0;
    let mut total_collateral = 0u64;
    let mut total_debt = 0u64;
    
    for position in &user_positions {
        total_collateral += position.supplied_balance;
        total_debt += position.borrowed_balance;
        
        if position.health_factor >= 2_000_000 {
            healthy_positions += 1;
        } else if position.health_factor >= 1_200_000 {
            warning_positions += 1;
        } else {
            risky_positions += 1;
        }
    }
    
    println!("   Healthy positions (HF >= 2.0): {}", healthy_positions);
    println!("   Warning positions (1.2 <= HF < 2.0): {}", warning_positions);
    println!("   Risky positions (HF < 1.2): {}", risky_positions);
    println!("   Total collateral: {}", format_amount(total_collateral));
    println!("   Total debt: {}", format_amount(total_debt));
    println!("   System leverage: {:.2}x", total_collateral as f64 / total_debt.max(1) as f64);
    
    // 5. Display top risky positions
    if risky_positions > 0 {
        println!();
        println!("⚠️  Top Risky Positions (Health Factor < 1.2)");
        println!("{}", "-".repeat(80));
        
        let mut risky = user_positions.clone();
        risky.sort_by_key(|p| p.health_factor);
        
        for (i, position) in risky.iter().take(5).enumerate() {
            if position.health_factor < 1_200_000 {
                println!("   {}. User: {}", i + 1, &position.user[..8]);
                println!("      Health factor: {:.2}", position.health_factor as f64 / 1_000_000.0);
                println!("      Supplied: {}", format_amount(position.supplied_balance));
                println!("      Borrowed: {}", format_amount(position.borrowed_balance));
                println!("      Liquidation threshold: {}", format_amount(position.liquidation_threshold));
            }
        }
    }
    
    // 6. Alert system
    println!();
    println!("🚨 Alert System");
    println!("{}", "-".repeat(80));
    
    if alerts.is_empty() {
        println!("   ✅ All systems normal. No alerts at this time.");
    } else {
        println!("   ⚠️  Found {} alert(s):", alerts.len());
        for (i, alert) in alerts.iter().enumerate() {
            println!("   {}. {}", i + 1, alert);
        }
    }
    
    // 7. Generate report
    println!();
    println!("📊 System Health Report");
    println!("{}", "-".repeat(80));
    
    let overall_health = calculate_system_health(&pool_states, &user_positions);
    
    println!("   Overall system health: {}/100", overall_health);
    println!("   Total pools monitored: {}", pool_states.len());
    println!("   Total users: {}", user_positions.len());
    println!("   Total value locked: {}", format_amount(total_collateral));
    println!("   Average health factor: {:.2}", 
        user_positions.iter().map(|p| p.health_factor).sum::<u64>() as f64 / user_positions.len().max(1) as f64 / 1_000_000.0);
    
    // 8. Recommendations
    println!();
    println!("💡 Recommendations");
    println!("{}", "-".repeat(80));
    
    if risky_positions > 0 {
        println!("   1. Monitor {} risky positions closely", risky_positions);
        println!("   2. Consider automated liquidation for HF < 1.1");
    }
    
    if total_debt > total_collateral * 3 / 4 {
        println!("   3. System leverage is high. Consider increasing collateral requirements");
    }
    
    // 9. Next steps
    println!();
    println!("🎉 Pool state query completed!");
    println!();
    println!("Next steps:");
    println!("1. Set up continuous monitoring with monitor_events example");
    println!("2. Configure automated alerts for risky positions");
    println!("3. Generate daily/weekly reports");
    println!("4. Integrate with dashboard for real-time visualization");
    
    Ok(())
}

// Helper functions
fn format_amount(amount: u64) -> String {
    if amount >= 1_000_000_000 {
        format!("{:.3} SUI", amount as f64 / 1_000_000_000.0)
    } else {
        format!("{} units", amount)
    }
}

fn print_pool_status(pool: &PoolConfig, state: &PoolState) {
    println!("🏦 {}", pool.name);
    println!("   Asset: {}", pool.asset);
    println!("   Address: {}", &pool.address[..16]);
    println!("   Status: {}", if state.is_active { "✅ Active" } else { "❌ Inactive" });
    println!("   Total supply: {}", format_amount(state.total_supply));
    println!("   Total borrowed: {}", format_amount(state.total_borrowed));
    println!("   Utilization: {:.1}%", state.utilization_rate as f64 / 10_000.0);
    println!("   Available: {}", format_amount(state.total_supply - state.total_borrowed));
    println!("   Supply APY: {:.2}%", state.supply_rate as f64 / 10_000.0);
    println!("   Borrow APY: {:.2}%", state.borrow_rate as f64 / 10_000.0);
    println!();
}

fn check_pool_alerts(pool: &PoolConfig, state: &PoolState, thresholds: &AlertThresholds) -> Vec<String> {
    let mut alerts = Vec::new();
    
    if state.utilization_rate > thresholds.max_utilization {
        alerts.push(format!("{}: High utilization ({:.1}% > {:.1}%)", 
            pool.name, state.utilization_rate as f64 / 10_000.0, thresholds.max_utilization as f64 / 10_000.0));
    }
    
    let available_liquidity = state.total_supply - state.total_borrowed;
    if available_liquidity < thresholds.min_liquidity {
        alerts.push(format!("{}: Low liquidity ({:.3} SUI < {:.3} SUI)", 
            pool.name, available_liquidity as f64 / 1_000_000_000.0, thresholds.min_liquidity as f64 / 1_000_000_000.0));
    }
    
    if !state.is_active {
        alerts.push(format!("{}: Pool is inactive", pool.name));
    }
    
    alerts
}

fn calculate_system_health(pool_states: &HashMap<String, PoolState>, user_positions: &[UserPosition]) -> u8 {
    // Simplified health calculation
    let mut score = 100;
    
    // Deduct for high utilization
    for state in pool_states.values() {
        if state.utilization_rate > 850_000 {
            score -= 10;
        }
    }
    
    // Deduct for risky positions
    let risky_count = user_positions.iter().filter(|p| p.health_factor < 1_200_000).count();
    score -= (risky_count * 5).min(30) as u8;
    
    score.max(0)
}

// Simulation functions
async fn simulate_query_pool_state(pool_address: &str) -> Result<PoolState> {
    tokio::time::sleep(Duration::from_millis(300)).await;
    
    // Generate realistic but varying data
    let seed = pool_address.chars().map(|c| c as u64).sum::<u64>();
    
    Ok(PoolState {
        is_active: true,
        total_supply: 10_000_000_000 + (seed % 5) * 2_000_000_000,
        total_borrowed: 4_500_000_000 + (seed % 3) * 1_000_000_000,
        utilization_rate: 450_000 + ((seed % 20) * 10_000) as u64,
        supply_rate: 35_000 + ((seed % 5) * 1_000) as u64,
        borrow_rate: 45_000 + ((seed % 5) * 1_000) as u64,
    })
}

async fn simulate_get_user_positions() -> Result<Vec<UserPosition>> {
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    let mut positions = Vec::new();
    
    // Generate sample user positions
    for i in 0..25 {
        let user_id = format!("user_{:02x}", i);
        let supplied = 500_000_000 + (i as u64) * 100_000_000;
        let borrowed = (supplied * (40 + (i % 30)) as u64) / 100;
        let health_factor = if borrowed == 0 { 
            10_000_000 
        } else { 
            (supplied * 1_000_000) / borrowed 
        };
        
        positions.push(UserPosition {
            user: user_id,
            supplied_balance: supplied,
            borrowed_balance: borrowed,
            health_factor,
            liquidation_threshold: (supplied * 85) / 100,
        });
    }
    
    Ok(positions)
}

// Data structures
enum Network {
    Testnet,
    Mainnet,
    Devnet,
}

struct MonitorConfig {
    network: Network,
    pools: Vec<PoolConfig>,
    refresh_interval: Duration,
    alert_thresholds: AlertThresholds,
}

struct PoolConfig {
    address: String,
    name: String,
    asset: String,
}

struct AlertThresholds {
    min_health_factor: u64,
    max_utilization: u64,
    min_liquidity: u64,
}

struct PoolState {
    is_active: bool,
    total_supply: u64,
    total_borrowed: u64,
    utilization_rate: u64,
    supply_rate: u64,
    borrow_rate: u64,
}

#[derive(Clone)]
struct UserPosition {
    user: String,
    supplied_balance: u64,
    borrowed_balance: u64,
    health_factor: u64,
    liquidation_threshold: u64,
}