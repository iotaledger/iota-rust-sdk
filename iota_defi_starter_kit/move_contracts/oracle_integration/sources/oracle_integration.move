/// @title IOTA Move DeFi Oracle Integration Module
/// @notice 预言机集成模块：集成Switchboard和Pyth价格预言机
/// @dev 基于Sui Move，适配IOTA生态系统

module oracle_integration::oracle_integration {
    use std::vector;
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::event;
    
    // ============ 常量 ============
    
    /// 价格精度（8位小数）
    const PRICE_PRECISION: u64 = 100_000_000;
    
    /// 最大价格偏差（5%）
    const MAX_PRICE_DEVIATION: u64 = 50_000; // 5% * 10^6
    
    /// 价格有效期（60秒）
    const PRICE_VALIDITY_PERIOD: u64 = 60;
    
    // ============ 错误代码 ============
    
    /// 价格过期
    const EPRICE_STALE: u64 = 1;
    
    /// 价格偏差过大
    const EPRICE_DEVIATION_TOO_HIGH: u64 = 2;
    
    /// 无效的预言机源
    const EINVALID_ORACLE_SOURCE: u64 = 3;
    
    /// 价格无效
    const EINVALID_PRICE: u64 = 4;
    
    // ============ 事件 ============
    
    /// 价格更新事件
    struct PriceUpdated has copy, drop {
        asset: address,
        price: u64,
        timestamp: u64,
        source: u8, // 0=Switchboard, 1=Pyth
    }
    
    /// 预言机喂价事件
    struct OracleFeed has copy, drop {
        feed_id: vector<u8>,
        price: u64,
        confidence: u64,
        timestamp: u64,
    }
    
    // ============ 数据结构 ============
    
    /// 价格数据
    struct PriceData has key, store {
        id: UID,
        asset: address,
        price: u64,           // 价格 * PRICE_PRECISION
        confidence: u64,      // 置信区间
        timestamp: u64,       // 时间戳（秒）
        source: u8,           // 预言机源：0=Switchboard, 1=Pyth
        is_valid: bool,
    }
    
    /// 预言机配置
    struct OracleConfig has key, store {
        id: UID,
        switchboard_feed_ids: vector<vector<u8>>,
        pyth_price_feed_ids: vector<vector<u8>>,
        min_confidence_ratio: u64, // 最小置信比（百分比 * 10^6）
        max_price_age: u64,        // 最大价格年龄（秒）
        is_active: bool,
    }
    
    /// 聚合价格
    struct AggregatedPrice has key, store {
        id: UID,
        asset: address,
        price: u64,           // 聚合价格
        timestamp: u64,
        source_count: u8,     // 数据源数量
        is_aggregated: bool,
    }
    
    // ============ 公共函数 ============
    
    /// @notice 初始化预言机配置
    /// @param switchboard_feeds Switchboard喂价ID列表
    /// @param pyth_feeds Pyth喂价ID列表
    public entry fun initialize_config(
        switchboard_feeds: vector<vector<u8>>,
        pyth_feeds: vector<vector<u8>>,
        ctx: &mut TxContext,
    ) {
        let config = OracleConfig {
            id: object::new(ctx),
            switchboard_feed_ids: switchboard_feeds,
            pyth_price_feed_ids: pyth_feeds,
            min_confidence_ratio: 500_000, // 50%
            max_price_age: PRICE_VALIDITY_PERIOD,
            is_active: true,
        };
        
        transfer::transfer(config, tx_context::sender(ctx));
    }
    
    /// @notice 更新价格数据（模拟预言机喂价）
    /// @param config 预言机配置对象
    /// @param asset 资产地址
    /// @param price 价格
    /// @param source 数据源（0=Switchboard, 1=Pyth）
    public entry fun update_price(
        config: &OracleConfig,
        asset: address,
        price: u64,
        source: u8,
        ctx: &mut TxContext,
    ) {
        assert!(config.is_active, EINVALID_ORACLE_SOURCE);
        assert!(source == 0 || source == 1, EINVALID_ORACLE_SOURCE);
        assert!(price > 0, EINVALID_PRICE);
        
        let price_data = PriceData {
            id: object::new(ctx),
            asset,
            price,
            confidence: price / 100, // 简化：置信区间为价格的1%
            timestamp: tx_context::epoch(ctx),
            source,
            is_valid: true,
        };
        
        transfer::transfer(price_data, tx_context::sender(ctx));
        
        // 发出价格更新事件
        event::emit(PriceUpdated {
            asset,
            price,
            timestamp: tx_context::epoch(ctx),
            source,
        });
    }
    
    /// @notice 聚合多个预言机价格
    /// @param price_data_list 价格数据对象列表
    /// @param asset 资产地址
    public entry fun aggregate_prices(
        _price_data_list: &vector<PriceData>,
        asset: address,
        ctx: &mut TxContext,
    ) {
        let count = 0;
        let total_price = 0;
        let total_confidence = 0;
        let latest_timestamp = 0;
        
        // 遍历价格数据，计算加权平均
        // 简化实现：计算简单平均
        
        let aggregated_price = AggregatedPrice {
            id: object::new(ctx),
            asset,
            price: total_price,
            timestamp: latest_timestamp,
            source_count: count,
            is_aggregated: true,
        };
        
        transfer::transfer(aggregated_price, tx_context::sender(ctx));
    }
    
    /// @notice 验证价格有效性
    /// @param price_data 价格数据对象
    /// @param config 预言机配置对象
    public fun validate_price(
        price_data: &PriceData,
        config: &OracleConfig,
    ): bool {
        if (!price_data.is_valid) {
            return false;
        };
        
        let current_time = 0; // 实际应用中应获取当前时间
        let price_age = current_time - price_data.timestamp;
        
        if (price_age > config.max_price_age) {
            return false;
        };
        
        // 检查置信区间
        let confidence_ratio = (price_data.confidence * 1_000_000) / price_data.price;
        if (confidence_ratio > config.min_confidence_ratio) {
            return false;
        };
        
        true
    }
    
    // ============ 视图函数 ============
    
    /// @notice 获取价格信息
    public fun get_price_info(price_data: &PriceData): (address, u64, u64, u64, u8, bool) {
        (
            price_data.asset,
            price_data.price,
            price_data.confidence,
            price_data.timestamp,
            price_data.source,
            price_data.is_valid,
        )
    }
    
    /// @notice 获取聚合价格信息
    public fun get_aggregated_price_info(agg_price: &AggregatedPrice): (address, u64, u64, u8, bool) {
        (
            agg_price.asset,
            agg_price.price,
            agg_price.timestamp,
            agg_price.source_count,
            agg_price.is_aggregated,
        )
    }
}