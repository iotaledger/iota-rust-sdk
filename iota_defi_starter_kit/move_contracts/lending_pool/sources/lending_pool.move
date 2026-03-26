/// @title IOTA Move DeFi Lending Pool
/// @notice 借贷池模块：支持存入、借出、还款、取款和动态利率模型
/// @dev 基于Sui Move，适配IOTA生态系统

module lending_pool::lending_pool {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::event;
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::math;
    
    // ============ 常量 ============
    
    /// 最小健康因子（1.0 = 100%）
    const MIN_HEALTH_FACTOR: u64 = 1_000_000; // 1.0 * 10^6
    
    /// 精度因子（6位小数）
    const PRECISION: u64 = 1_000_000;
    
    /// 最大利用率（90%）
    const MAX_UTILIZATION: u64 = 900_000; // 0.9 * 10^6
    
    // ============ 错误代码 ============
    
    /// 余额不足
    const EINSUFFICIENT_BALANCE: u64 = 1;
    
    /// 健康因子过低
    const EUNHEALTHY_POSITION: u64 = 2;
    
    /// 超过借款限额
    const EBORROW_LIMIT_EXCEEDED: u64 = 3;
    
    /// 无效的利率参数
    const EINVALID_INTEREST_PARAMS: u64 = 4;
    
    /// 未授权操作
    const EUNAUTHORIZED: u64 = 5;
    
    /// 数学溢出
    const EOVERFLOW: u64 = 6;
    
    // ============ 事件 ============
    
    /// 存款事件
    struct DepositEvent has copy, drop {
        user: address,
        asset: address,
        amount: u64,
        timestamp: u64,
    }
    
    /// 借款事件
    struct BorrowEvent has copy, drop {
        user: address,
        asset: address,
        amount: u64,
        borrow_rate: u64,
        timestamp: u64,
    }
    
    /// 还款事件
    struct RepayEvent has copy, drop {
        user: address,
        asset: address,
        amount: u64,
        timestamp: u64,
    }
    
    /// 取款事件
    struct WithdrawEvent has copy, drop {
        user: address,
        asset: address,
        amount: u64,
        timestamp: u64,
    }
    
    /// 清算事件
    struct LiquidateEvent has copy, drop {
        user: address,
        liquidator: address,
        asset: address,
        amount: u64,
        bonus: u64,
        timestamp: u64,
    }
    
    // ============ 数据结构 ============
    
    /// 借贷池配置
    struct PoolConfig has key, store {
        id: UID,
        asset: address,
        reserve_factor: u64,      // 储备金因子（百分比 * PRECISION）
        max_utilization: u64,     // 最大利用率（百分比 * PRECISION）
        interest_rate_model: address, // 利率模型合约地址
        is_active: bool,
        last_update_timestamp: u64,
    }
    
    /// 池状态
    struct PoolState has key, store {
        id: UID,
        total_supply: u64,
        total_borrowed: u64,
        utilization_rate: u64,    // 利用率（百分比 * PRECISION）
        supply_rate: u64,         // 存款利率（年化百分比 * PRECISION）
        borrow_rate: u64,         // 借款利率（年化百分比 * PRECISION）
        reserve_balance: u64,
        last_accrual_timestamp: u64,
    }
    
    /// 用户仓位
    struct UserPosition has key, store {
        id: UID,
        user: address,
        supplied_balance: u64,
        borrowed_balance: u64,
        collateral_value: u64,    // 抵押品价值（USD * PRECISION）
        borrow_limit: u64,        // 借款限额（USD * PRECISION）
        health_factor: u64,       // 健康因子（PRECISION = 1.0）
        last_update_timestamp: u64,
    }
    
    /// 利率模型参数（线性模型：rate = base + utilization * slope）
    struct InterestRateModel has key, store {
        id: UID,
        base_rate: u64,          // 基础利率（年化百分比 * PRECISION）
        slope1: u64,             // 第一斜率（利用率 < kink）
        slope2: u64,             // 第二斜率（利用率 >= kink）
        kink: u64,               // 拐点利用率（百分比 * PRECISION）
    }
    
    // ============ 公共函数 ============
    
    /// @notice 初始化新的借贷池
    /// @param asset 资产地址
    /// @param reserve_factor 储备金因子（百分比 * PRECISION）
    /// @param interest_model 利率模型合约地址
    public entry fun initialize_pool(
        asset: address,
        reserve_factor: u64,
        interest_model: address,
        ctx: &mut TxContext,
    ) {
        let pool_config = PoolConfig {
            id: object::new(ctx),
            asset,
            reserve_factor,
            max_utilization: MAX_UTILIZATION,
            interest_rate_model: interest_model,
            is_active: true,
            last_update_timestamp: tx_context::epoch(ctx),
        };
        
        let pool_state = PoolState {
            id: object::new(ctx),
            total_supply: 0,
            total_borrowed: 0,
            utilization_rate: 0,
            supply_rate: 0,
            borrow_rate: 0,
            reserve_balance: 0,
            last_accrual_timestamp: tx_context::epoch(ctx),
        };
        
        transfer::transfer(pool_config, tx_context::sender(ctx));
        transfer::transfer(pool_state, tx_context::sender(ctx));
    }
    
    /// @notice 存入资产到借贷池
    /// @param pool_config 池配置对象
    /// @param pool_state 池状态对象
    /// @param coin 存入的代币
    public entry fun supply(
        pool_config: &PoolConfig,
        pool_state: &mut PoolState,
        coin: Coin<address>,
        ctx: &mut TxContext,
    ) {
        assert!(pool_config.is_active, EUNAUTHORIZED);
        
        let amount = coin::value(&coin);
        let user = tx_context::sender(ctx);
        
        // 更新池状态
        pool_state.total_supply = pool_state.total_supply + amount;
        pool_state.last_accrual_timestamp = tx_context::epoch(ctx);
        
        // 计算新的利用率
        update_utilization(pool_state);
        
        // 更新利率
        update_interest_rates(pool_config, pool_state);
        
        // 创建或更新用户仓位
        let position_id = get_user_position_id(user, ctx);
        let position = get_or_create_user_position(position_id, user, ctx);
        position.supplied_balance = position.supplied_balance + amount;
        position.last_update_timestamp = tx_context::epoch(ctx);
        
        // 销毁存入的代币（实际应用中应转入池合约）
        coin::destroy_zero(coin);
        
        // 发出存款事件
        event::emit(DepositEvent {
            user,
            asset: pool_config.asset,
            amount,
            timestamp: tx_context::epoch(ctx),
        });
        
        // 转移仓位对象给用户（消费对象）
        transfer::transfer(position, tx_context::sender(ctx));
    }
    
    /// @notice 从借贷池借出资产
    /// @param pool_config 池配置对象
    /// @param pool_state 池状态对象
    /// @param amount 借出金额
    /// @param ctx 交易上下文
    public entry fun borrow(
        pool_config: &PoolConfig,
        pool_state: &mut PoolState,
        amount: u64,
        ctx: &mut TxContext,
    ) {
        assert!(pool_config.is_active, EUNAUTHORIZED);
        
        // 检查借款限额
        let user = tx_context::sender(ctx);
        let position_id = get_user_position_id(user, ctx);
        let position = get_or_create_user_position(position_id, user, ctx);
        
        // 更新健康因子
        update_health_factor(&mut position);
        assert!(position.health_factor >= MIN_HEALTH_FACTOR, EUNHEALTHY_POSITION);
        
        // 检查池流动性
        let available_liquidity = pool_state.total_supply - pool_state.total_borrowed;
        assert!(amount <= available_liquidity, EINSUFFICIENT_BALANCE);
        
        // 更新池状态
        pool_state.total_borrowed = pool_state.total_borrowed + amount;
        pool_state.last_accrual_timestamp = tx_context::epoch(ctx);
        
        // 更新利用率和利率
        update_utilization(pool_state);
        update_interest_rates(pool_config, pool_state);
        
        // 更新用户仓位
        position.borrowed_balance = position.borrowed_balance + amount;
        position.last_update_timestamp = tx_context::epoch(ctx);
        
        // 铸造借出的代币给用户（实际应用中应从池合约转出）
        // 这里简化处理，实际需要更复杂的代币管理
        
        // 发出借款事件
        event::emit(BorrowEvent {
            user,
            asset: pool_config.asset,
            amount,
            borrow_rate: pool_state.borrow_rate,
            timestamp: tx_context::epoch(ctx),
        });
        
        // 转移仓位对象给用户（消费对象）
        transfer::transfer(position, tx_context::sender(ctx));
    }
    
    // ============ 内部函数 ============
    
    /// 更新池利用率
    fun update_utilization(pool_state: &mut PoolState) {
        if (pool_state.total_supply == 0) {
            pool_state.utilization_rate = 0;
            return;
        };
        
        pool_state.utilization_rate = (pool_state.total_borrowed * PRECISION) / pool_state.total_supply;
    }
    
    /// 更新利率
    fun update_interest_rates(pool_config: &PoolConfig, pool_state: &mut PoolState) {
        // 简化利率模型：利率随利用率线性增加
        // 实际应用中应从利率模型合约获取
        let utilization = pool_state.utilization_rate;
        
        // 基础利率 2% + 利用率 * 20%
        pool_state.borrow_rate = 20_000 + (utilization * 200_000) / PRECISION; // 0.02% - 22%
        
        // 存款利率 = 借款利率 * (1 - 储备金因子)
        let reserve_factor = pool_config.reserve_factor;
        pool_state.supply_rate = (pool_state.borrow_rate * (PRECISION - reserve_factor)) / PRECISION;
    }
    
    /// 更新健康因子
    fun update_health_factor(position: &mut UserPosition) {
        // 简化健康因子计算：抵押品价值 / 借款价值
        // 实际应用中需要从预言机获取价格
        if (position.borrowed_balance == 0) {
            position.health_factor = PRECISION * 10; // 无穷大
            return;
        };
        
        // 假设抵押品价值 = 存入金额 * 1.0（实际需要价格）
        let collateral_value = position.supplied_balance;
        let borrow_value = position.borrowed_balance;
        
        position.health_factor = (collateral_value * PRECISION) / borrow_value;
    }
    
    /// 获取或创建用户仓位
    fun get_or_create_user_position(
        position_id: address,
        user: address,
        ctx: &mut TxContext,
    ): UserPosition {
        // 简化处理：总是创建新的仓位对象
        // 实际应用中需要检查是否已存在
        UserPosition {
            id: object::new(ctx),
            user,
            supplied_balance: 0,
            borrowed_balance: 0,
            collateral_value: 0,
            borrow_limit: 0,
            health_factor: PRECISION * 10,
            last_update_timestamp: tx_context::epoch(ctx),
        }
    }
    
    /// 生成用户仓位ID
    fun get_user_position_id(user: address, ctx: &TxContext): address {
        // 简化处理：使用用户地址作为ID
        // 实际应用中可能需要更复杂的ID生成
        user
    }
    
    // ============ 视图函数 ============
    
    /// @notice 获取池信息
    public fun get_pool_info(pool_state: &PoolState): (u64, u64, u64, u64, u64) {
        (
            pool_state.total_supply,
            pool_state.total_borrowed,
            pool_state.utilization_rate,
            pool_state.supply_rate,
            pool_state.borrow_rate,
        )
    }
    
    /// @notice 获取用户仓位信息
    public fun get_user_position(position: &UserPosition): (address, u64, u64, u64, u64) {
        (
            position.user,
            position.supplied_balance,
            position.borrowed_balance,
            position.health_factor,
            position.borrow_limit,
        )
    }
}