//! Example: Monitor DeFi events in real-time
//!
//! This example demonstrates how to:
//! 1. Subscribe to DeFi contract events
//! 2. Process events in real-time
//! 3. Generate alerts and notifications
//! 4. Maintain event history and analytics

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    println!("🚀 Starting IOTA Move DeFi Starter Kit - Event Monitor Example");
    println!("📡 Real-time event monitoring and alert system");
    
    // 1. Configuration
    println!("⚙️  Loading event monitoring configuration...");
    
    let config = EventMonitorConfig {
        network: Network::Testnet,
        pools: vec![
            "0x1234567890abcdef".to_string(), // Lending pool
            "0xfedcba9876543210".to_string(), // Flash loan pool
            "0xabcdef1234567890".to_string(), // USDC pool
        ],
        event_types: vec![
            EventType::Deposit,
            EventType::Borrow,
            EventType::Repay,
            EventType::Withdraw,
            EventType::Liquidation,
            EventType::FlashLoan,
        ],
        alert_channels: vec![
            AlertChannel::Console,
            AlertChannel::LogFile,
            AlertChannel::Webhook,
        ],
        max_events_per_second: 100,
    };
    
    println!("📋 Monitoring configuration:");
    println!("   Network: {:?}", config.network);
    println!("   Pools: {}", config.pools.len());
    println!("   Event types: {}", config.event_types.len());
    println!("   Alert channels: {}", config.alert_channels.len());
    
    // 2. Initialize event processor
    println!("🔄 Initializing event processor...");
    
    let (event_tx, mut event_rx) = mpsc::channel(1000);
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    
    // Start event simulator
    let simulator_handle = tokio::spawn(event_simulator(event_tx, config.clone()));
    
    // Start alert processor
    let alert_handle = tokio::spawn(alert_processor(alert_rx));
    
    // 3. Start monitoring
    println!("🎬 Starting event monitoring...");
    println!("   Press Ctrl+C to stop");
    println!();
    
    let start_time = Instant::now();
    let mut event_counts = HashMap::new();
    let mut event_history = Vec::new();
    let mut last_stats_time = Instant::now();
    
    // 4. Main event processing loop
    while let Some(event) = event_rx.recv().await {
        // Update counters
        *event_counts.entry(event.event_type.clone()).or_insert(0) += 1;
        
        // Store in history (with limit)
        event_history.push(event.clone());
        if event_history.len() > 1000 {
            event_history.remove(0);
        }
        
        // Process event
        process_event(&event, &alert_tx).await?;
        
        // Display statistics periodically
        if last_stats_time.elapsed() >= Duration::from_secs(10) {
            display_statistics(&event_counts, start_time.elapsed());
            last_stats_time = Instant::now();
        }
        
        // Check for exit condition (simulated)
        if event_counts.values().sum::<u64>() >= 50 {
            println!();
            println!("📊 Reached sample limit of 50 events. Stopping simulation...");
            break;
        }
    }
    
    // 5. Cleanup
    drop(alert_tx); // Close alert channel
    
    // Wait for tasks to complete
    let _ = simulator_handle.await;
    let _ = alert_handle.await;
    
    // 6. Final statistics
    println!();
    println!("📈 Final Event Statistics");
    println!("{}", "-".repeat(80));
    
    display_statistics(&event_counts, start_time.elapsed());
    
    // 7. Event analysis
    println!();
    println!("🔍 Event Analysis");
    println!("{}", "-".repeat(80));
    
    analyze_events(&event_history);
    
    // 8. System recommendations
    println!();
    println!("💡 System Recommendations");
    println!("{}", "-".repeat(80));
    
    generate_recommendations(&event_history, &event_counts);
    
    // 9. Export options
    println!();
    println!("💾 Export Options");
    println!("{}", "-".repeat(80));
    
    println!("   1. Event history can be exported to JSON/CSV");
    println!("   2. Real-time alerts can be sent to Slack/Telegram");
    println!("   3. Metrics can be integrated with Prometheus/Grafana");
    println!("   4. Historical data can be stored in database");
    
    println!();
    println!("🎉 Event monitoring simulation completed!");
    println!();
    println!("Next steps:");
    println!("1. Deploy to production with real event streams");
    println!("2. Configure additional alert channels (Email, SMS)");
    println!("3. Implement event correlation for complex patterns");
    println!("4. Set up automated response mechanisms");
    
    Ok(())
}

// Event processing functions
async fn process_event(event: &DeFiEvent, alert_tx: &mpsc::Sender<Alert>) -> Result<()> {
    // Format event for display
    let timestamp = format!("[{:02}:{:02}:{:02}]", 
        event.timestamp / 3600,
        (event.timestamp % 3600) / 60,
        event.timestamp % 60);
    
    match &event.event_type {
        EventType::Deposit => {
            println!("{} 💰 Deposit: User {} deposited {} {}", 
                timestamp, &event.user[..8], format_amount(event.amount), event.asset);
        }
        EventType::Borrow => {
            println!("{} 💸 Borrow: User {} borrowed {} {} at {:.2}% APY", 
                timestamp, &event.user[..8], format_amount(event.amount), event.asset,
                event.additional_data.get("borrow_rate").unwrap_or(&0.0));
            
            // Check for risky borrow
            if event.amount > 10_000_000_000 {
                let alert = Alert::new(
                    AlertLevel::Warning,
                    format!("Large borrow: {} borrowed {} {}", 
                        &event.user[..8], format_amount(event.amount), event.asset),
                    event.timestamp,
                );
                let _ = alert_tx.send(alert).await;
            }
        }
        EventType::Liquidation => {
            println!("{} ⚡ Liquidation: User {} liquidated by {} for {} {}", 
                timestamp, &event.user[..8], &event.liquidator[..8], 
                format_amount(event.amount), event.asset);
            
            let alert = Alert::new(
                AlertLevel::Critical,
                format!("Liquidation: User {} lost {} {}", 
                    &event.user[..8], format_amount(event.amount), event.asset),
                event.timestamp,
            );
            let _ = alert_tx.send(alert).await;
        }
        EventType::FlashLoan => {
            println!("{} ⚡ Flash Loan: User {} executed {} {} flash loan", 
                timestamp, &event.user[..8], format_amount(event.amount), event.asset);
        }
        _ => {
            println!("{} 📝 {}: User {} - {} {}", 
                timestamp, format_event_type(&event.event_type), 
                &event.user[..8], format_amount(event.amount), event.asset);
        }
    }
    
    Ok(())
}

fn display_statistics(event_counts: &HashMap<EventType, u64>, duration: Duration) {
    let total_events: u64 = event_counts.values().sum();
    let events_per_second = total_events as f64 / duration.as_secs_f64();
    
    println!();
    println!("📊 Live Statistics ({} events total)", total_events);
    println!("{}", "-".repeat(80));
    println!("   Duration: {:.1}s", duration.as_secs_f64());
    println!("   Events/sec: {:.2}", events_per_second);
    println!("   Event distribution:");
    
    let mut sorted_counts: Vec<_> = event_counts.iter().collect();
    sorted_counts.sort_by_key(|(_, &count)| std::cmp::Reverse(count));
    
    for (event_type, count) in sorted_counts {
        let percentage = (*count as f64 / total_events as f64) * 100.0;
        println!("     {}: {} ({:.1}%)", format_event_type(event_type), count, percentage);
    }
}

fn analyze_events(history: &[DeFiEvent]) {
    if history.is_empty() {
        return;
    }
    
    // Find most active user
    let mut user_activity: HashMap<String, u64> = HashMap::new();
    let mut asset_volumes: HashMap<String, u64> = HashMap::new();
    
    for event in history {
        *user_activity.entry(event.user.clone()).or_insert(0) += 1;
        *asset_volumes.entry(event.asset.clone()).or_insert(0) += event.amount;
    }
    
    let most_active_user = user_activity.iter()
        .max_by_key(|(_, &count)| count)
        .map(|(user, count)| (user, count))
        .unwrap_or((&"none".to_string(), &0));
    
    let highest_volume_asset = asset_volumes.iter()
        .max_by_key(|(_, &volume)| volume)
        .map(|(asset, volume)| (asset, volume))
        .unwrap_or((&"none".to_string(), &0));
    
    println!("   Most active user: {} ({} events)", 
        &most_active_user.0[..8], most_active_user.1);
    println!("   Highest volume asset: {} ({} total)", 
        highest_volume_asset.0, format_amount(*highest_volume_asset.1));
    
    // Check for patterns
    let liquidation_count = history.iter()
        .filter(|e| matches!(e.event_type, EventType::Liquidation))
        .count();
    
    if liquidation_count > 0 {
        println!("   Liquidations detected: {}", liquidation_count);
        println!("   💡 Consider reviewing risk parameters");
    }
}

fn generate_recommendations(history: &[DeFiEvent], event_counts: &HashMap<EventType, u64>) {
    // Simple recommendation engine
    let borrow_count = event_counts.get(&EventType::Borrow).unwrap_or(&0);
    let deposit_count = event_counts.get(&EventType::Deposit).unwrap_or(&0);
    let liquidation_count = event_counts.get(&EventType::Liquidation).unwrap_or(&0);
    
    if *borrow_count > *deposit_count * 2 {
        println!("   ⚠️  Borrowing activity is high compared to deposits");
        println!("   💡 Consider adjusting interest rates to encourage deposits");
    }
    
    if *liquidation_count > 0 {
        println!("   ⚠️  Liquidations occurred during monitoring period");
        println!("   💡 Review liquidation parameters and user education");
    }
    
    // Check for large transactions
    let large_tx_count = history.iter()
        .filter(|e| e.amount > 50_000_000_000)
        .count();
    
    if large_tx_count > 0 {
        println!("   ⚠️  {} large transactions detected", large_tx_count);
        println!("   💡 Implement transaction size limits or additional verification");
    }
}

// Helper functions
fn format_amount(amount: u64) -> String {
    if amount >= 1_000_000_000 {
        format!("{:.3}", amount as f64 / 1_000_000_000.0)
    } else {
        format!("{}", amount)
    }
}

fn format_event_type(event_type: &EventType) -> &str {
    match event_type {
        EventType::Deposit => "Deposit",
        EventType::Borrow => "Borrow",
        EventType::Repay => "Repay",
        EventType::Withdraw => "Withdraw",
        EventType::Liquidation => "Liquidation",
        EventType::FlashLoan => "FlashLoan",
    }
}

// Simulation functions
async fn event_simulator(mut tx: mpsc::Sender<DeFiEvent>, config: EventMonitorConfig) {
    let mut event_id = 0;
    let start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let users = vec!["alice", "bob", "charlie", "david", "eve"];
    let assets = vec!["SUI", "USDC", "ETH"];
    let event_types = config.event_types.clone();
    
    while event_id < 50 { // Simulate 50 events
        event_id += 1;
        
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - start_time;
        
        let user = users[event_id as usize % users.len()].to_string();
        let asset = assets[event_id as usize % assets.len()].to_string();
        let event_type = event_types[event_id as usize % event_types.len()].clone();
        
        // Generate realistic amounts
        let amount = match event_type {
            EventType::Deposit => 1_000_000_000 + (event_id as u64 % 10) * 500_000_000,
            EventType::Borrow => 500_000_000 + (event_id as u64 % 8) * 300_000_000,
            EventType::Liquidation => 2_000_000_000 + (event_id as u64 % 5) * 1_000_000_000,
            EventType::FlashLoan => 10_000_000_000 + (event_id as u64 % 3) * 5_000_000_000,
            _ => 100_000_000 + (event_id as u64 % 5) * 50_000_000,
        };
        
        let event = DeFiEvent {
            id: event_id,
            event_type,
            user: user.clone(),
            asset: asset.clone(),
            amount,
            timestamp: elapsed,
            liquidator: if event_id % 10 == 0 {
                Some(users[(event_id as usize + 1) % users.len()].to_string())
            } else {
                None
            },
            additional_data: {
                let mut map = HashMap::new();
                if event_id % 3 == 0 {
                    map.insert("borrow_rate".to_string(), 4.5);
                }
                map
            },
        };
        
        if tx.send(event).await.is_err() {
            break;
        }
        
        // Random delay between events
        let delay_ms = 100 + (event_id as u64 % 400);
        time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

async fn alert_processor(mut rx: mpsc::Receiver<Alert>) {
    while let Some(alert) = rx.recv().await {
        let prefix = match alert.level {
            AlertLevel::Info => "ℹ️ ",
            AlertLevel::Warning => "⚠️ ",
            AlertLevel::Critical => "🚨",
        };
        
        println!("{} ALERT: {}", prefix, alert.message);
        
        // In production, would send to various channels:
        // - Email
        // - Slack/Telegram
        // - SMS
        // - Dashboard
    }
}

// Data structures
#[derive(Clone)]
enum Network {
    Testnet,
    Mainnet,
    Devnet,
}

#[derive(Clone)]
enum EventType {
    Deposit,
    Borrow,
    Repay,
    Withdraw,
    Liquidation,
    FlashLoan,
}

#[derive(Clone)]
enum AlertChannel {
    Console,
    LogFile,
    Webhook,
    Email,
    Sms,
}

#[derive(Clone)]
struct EventMonitorConfig {
    network: Network,
    pools: Vec<String>,
    event_types: Vec<EventType>,
    alert_channels: Vec<AlertChannel>,
    max_events_per_second: u32,
}

#[derive(Clone)]
struct DeFiEvent {
    id: u64,
    event_type: EventType,
    user: String,
    asset: String,
    amount: u64,
    timestamp: u64,
    liquidator: Option<String>,
    additional_data: HashMap<String, f64>,
}

enum AlertLevel {
    Info,
    Warning,
    Critical,
}

struct Alert {
    level: AlertLevel,
    message: String,
    timestamp: u64,
}

impl Alert {
    fn new(level: AlertLevel, message: String, timestamp: u64) -> Self {
        Self { level, message, timestamp }
    }
}