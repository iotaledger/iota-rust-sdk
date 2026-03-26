/// @title IOTA Move DeFi Liquidation Module
/// @notice 清算模块：抵押不足仓位的自动清算
/// @dev 基于Sui Move，适配IOTA生态系统

module liquidation::liquidation {
    use std::vector;
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::event;
    use sui::coin::{Self, Coin};
    
    // ============ 常量 ============
    
    /// 最小健康因子（1.0 = 100%）
    const MIN_HEALTH_FACTOR: u64 = 1_000_000; // 1.0 * 10^6
    
    /// 清算惩罚率（8%）
    const LIQUIDATION_PENALTY_RATE: u64 = 80_000; // 8% * 10^6
    
    /// 清算奖金率（5%）
    const LIQUIDATION_BONUS_RATE: u64 = 50_000; // 5% * 10^6
    
    /// 精度因子（6位小数）
    const PRECISION: u64 = 1_000_000;
    
    // ============ 错误代码 ============
    
    /// 仓位健康
    const EPOSITION_HEALTHY: u64 = 1;
    
    /// 清算金额不足
    const ELIQUIDATION_AMOUNT_INSUFFICIENT: u64 = 2;
    
    /// 无效的清算者
    const EINVALID_LIQUIDATOR: u64 = 3;
    
    /// 清算已执行
    const ELIQUIDATION_EXECUTED: u64 = 4;
    
    // ============ 事件 ============
    
    /// 清算触发事件
    struct LiquidationTriggered has copy, drop {
        user: address,
        liquidator: address,
        asset: address,
        amount: u64,
        health_factor: u64,
        timestamp: u64,
    }
    
    /// 清算完成事件
    struct LiquidationCompleted has copy, drop {
        user: address,
        liquidator: address,
        asset: address,
        amount_liquidated: u64,
        bonus_amount: u64,
        timestamp: u64,
    }
    
    // ============ 数据结构 ============
    
    /// 清算记录
    struct LiquidationRecord has key, store {
        id: UID,
        user: address,
        liquidator: address,
        asset: address,
        amount_liquidated: u64,
        bonus_amount: u64,
        health_factor_before: u64,
        health_factor_after: u64,
        timestamp: u64,
        is_completed: bool,
    }
    
    /// 仓位健康状态
    struct PositionHealth has key, store {
        id: UID,
        user: address,
        asset: address,
        supplied_amount: u64,
        borrowed_amount: u64,
        collateral_value: u64,    // 抵押品价值（USD * PRECISION）
        health_factor: u64,       // 健康因子（PRECISION = 1.0）
        last_update_timestamp: u64,
        is_liquidatable: bool,
    }
    
    /// 清算配置
    struct LiquidationConfig has key, store {
        id: UID,
        min_health_factor: u64,
        liquidation_penalty_rate: u64,
        liquidation_bonus_rate: u64,
        max_liquidation_amount_ratio: u64, // 最大清算比例（百分比 * PRECISION）
        is_active: bool,
    }
    
    // ============ 公共函数 ============
    
    /// @notice 初始化清算配置
    public entry fun initialize_config(
        ctx: &mut TxContext,
    ) {
        let config = LiquidationConfig {
            id: object::new(ctx),
            min_health_factor: MIN_HEALTH_FACTOR,
            liquidation_penalty_rate: LIQUIDATION_PENALTY_RATE,
            liquidation_bonus_rate: LIQUIDATION_BONUS_RATE,
            max_liquidation_amount_ratio: 500_000, // 50%
            is_active: true,
        };
        
        transfer::transfer(config, tx_context::sender(ctx));
    }
    
    /// @notice 检查仓位是否可清算
    /// @param position 仓位健康状态对象
    /// @param config 清算配置对象
    public entry fun check_liquidation_status(
        position: &mut PositionHealth,
        config: &LiquidationConfig,
        ctx: &mut TxContext,
    ) {
        assert!(config.is_active, EINVALID_LIQUIDATOR);
        
        // 更新健康因子（实际应用中应从预言机获取价格）
        update_health_factor(position);
        
        // 检查是否可清算
        position.is_liquidatable = position.health_factor < config.min_health_factor;
        
        position.last_update_timestamp = tx_context::epoch(ctx);
    }
    
    /// @notice 执行清算
    /// @param position 仓位健康状态对象
    /// @param config 清算配置对象
    /// @param liquidation_amount 清算金额
    /// @param ctx 交易上下文
    public entry fun execute_liquidation(
        position: &mut PositionHealth,
        config: &LiquidationConfig,
        liquidation_amount: u64,
        ctx: &mut TxContext,
    ) {
        assert!(config.is_active, EINVALID_LIQUIDATOR);
        assert!(position.is_liquidatable, EPOSITION_HEALTHY);
        
        let liquidator = tx_context::sender(ctx);
        
        // 计算最大可清算金额
        let max_liquidation_amount = (position.borrowed_amount * config.max_liquidation_amount_ratio) / PRECISION;
        assert!(liquidation_amount <= max_liquidation_amount, ELIQUIDATION_AMOUNT_INSUFFICIENT);
        
        // 计算清算惩罚和奖金
        let penalty_amount = (liquidation_amount * config.liquidation_penalty_rate) / PRECISION;
        let bonus_amount = (liquidation_amount * config.liquidation_bonus_rate) / PRECISION;
        
        let health_factor_before = position.health_factor;
        
        // 更新仓位状态
        position.borrowed_amount = position.borrowed_amount - liquidation_amount;
        update_health_factor(position);
        
        let health_factor_after = position.health_factor;
        
        // 创建清算记录
        let record = LiquidationRecord {
            id: object::new(ctx),
            user: position.user,
            liquidator,
            asset: position.asset,
            amount_liquidated: liquidation_amount,
            bonus_amount,
            health_factor_before,
            health_factor_after,
            timestamp: tx_context::epoch(ctx),
            is_completed: true,
        };
        
        transfer::transfer(record, liquidator);
        
        // 发出清算事件
        event::emit(LiquidationTriggered {
            user: position.user,
            liquidator,
            asset: position.asset,
            amount: liquidation_amount,
            health_factor: health_factor_before,
            timestamp: tx_context::epoch(ctx),
        });
        
        event::emit(LiquidationCompleted {
            user: position.user,
            liquidator,
            asset: position.asset,
            amount_liquidated: liquidation_amount,
            bonus_amount,
            timestamp: tx_context::epoch(ctx),
        });
    }
    
    /// @notice 批量检查多个仓位
    /// @param positions 仓位健康状态对象列表
    /// @param config 清算配置对象
    public entry fun batch_check_positions(
        positions: &mut vector<PositionHealth>,
        config: &LiquidationConfig,
        ctx: &mut TxContext,
    ) {
        let i = 0;
        let length = vector::length(positions);
        
        while (i < length) {
            let position = vector::borrow_mut(positions, i);
            check_liquidation_status(position, config, ctx);
            i = i + 1;
        };
    }
    
    // ============ 内部函数 ============
    
    /// 更新健康因子
    fun update_health_factor(position: &mut PositionHealth) {
        if (position.borrowed_amount == 0) {
            position.health_factor = PRECISION * 10; // 无穷大
            return;
        };
        
        // 简化：健康因子 = 抵押品价值 / 借款价值
        // 实际应用中需要从预言机获取价格
        position.health_factor = (position.collateral_value * PRECISION) / position.borrowed_amount;
    }
    
    /// 计算可清算金额
    fun calculate_liquidatable_amount(
        position: &PositionHealth,
        config: &LiquidationConfig,
    ): u64 {
        if (!position.is_liquidatable) {
            return 0;
        };
        
        let max_amount = (position.borrowed_amount * config.max_liquidation_amount_ratio) / PRECISION;
        
        // 确保清算后健康因子恢复正常
        let needed_reduction = position.borrowed_amount - ((position.collateral_value * PRECISION) / config.min_health_factor);
        
        if (needed_reduction < max_amount) {
            needed_reduction
        } else {
            max_amount
        }
    }
    
    // ============ 视图函数 ============
    
    /// @notice 获取清算记录信息
    public fun get_liquidation_record(record: &LiquidationRecord): (address, address, address, u64, u64, u64, u64, u64, bool) {
        (
            record.user,
            record.liquidator,
            record.asset,
            record.amount_liquidated,
            record.bonus_amount,
            record.health_factor_before,
            record.health_factor_after,
            record.timestamp,
            record.is_completed,
        )
    }
    
    /// @notice 获取仓位健康信息
    public fun get_position_health(position: &PositionHealth): (address, address, u64, u64, u64, u64, u64, bool) {
        (
            position.user,
            position.asset,
            position.supplied_amount,
            position.borrowed_amount,
            position.collateral_value,
            position.health_factor,
            position.last_update_timestamp,
            position.is_liquidatable,
        )
    }
}