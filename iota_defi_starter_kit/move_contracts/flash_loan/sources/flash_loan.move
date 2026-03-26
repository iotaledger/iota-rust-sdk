/// @title IOTA Move DeFi Flash Loan Module
/// @notice 闪电贷模块：支持单交易借-用-还的无抵押贷款
/// @dev 基于Sui Move，适配IOTA生态系统

module flash_loan::flash_loan {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::event;
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    
    // ============ 常量 ============
    
    /// 闪电贷手续费率（0.09%）
    const FLASH_LOAN_FEE_RATE: u64 = 900; // 0.09% * 10^6
    
    /// 精度因子（6位小数）
    const PRECISION: u64 = 1_000_000;
    
    // ============ 错误代码 ============
    
    /// 余额不足
    const EINSUFFICIENT_BALANCE: u64 = 1;
    
    /// 手续费不足
    const EINSUFFICIENT_FEE: u64 = 2;
    
    /// 闪电贷未在同一交易中归还
    const EFLASH_LOAN_NOT_REPAID: u64 = 3;
    
    /// 无效的接收者
    const EINVALID_RECEIVER: u64 = 4;
    
    // ============ 事件 ============
    
    /// 闪电贷发起事件
    struct FlashLoanInitiated has copy, drop {
        borrower: address,
        asset: address,
        amount: u64,
        fee: u64,
        timestamp: u64,
    }
    
    /// 闪电贷归还事件
    struct FlashLoanRepaid has copy, drop {
        borrower: address,
        asset: address,
        amount: u64,
        fee: u64,
        timestamp: u64,
    }
    
    // ============ 数据结构 ============
    
    /// 闪电贷池
    struct FlashLoanPool has key, store {
        id: UID,
        asset: address,
        total_liquidity: u64,
        available_liquidity: u64,
        total_fees_earned: u64,
        is_active: bool,
    }
    
    /// 闪电贷记录
    struct FlashLoanRecord has key, store {
        id: UID,
        borrower: address,
        asset: address,
        amount: u64,
        fee: u64,
        initiation_timestamp: u64,
        repaid: bool,
    }
    
    // ============ 公共函数 ============
    
    /// @notice 初始化闪电贷池
    /// @param asset 资产地址
    public entry fun initialize_pool(
        asset: address,
        ctx: &mut TxContext,
    ) {
        let pool = FlashLoanPool {
            id: object::new(ctx),
            asset,
            total_liquidity: 0,
            available_liquidity: 0,
            total_fees_earned: 0,
            is_active: true,
        };
        
        transfer::transfer(pool, tx_context::sender(ctx));
    }
    
    /// @notice 提供流动性到闪电贷池
    /// @param pool 闪电贷池对象
    /// @param coin 提供的代币
    public entry fun provide_liquidity(
        pool: &mut FlashLoanPool,
        coin: Coin<address>,
        ctx: &mut TxContext,
    ) {
        assert!(pool.is_active, EINVALID_RECEIVER);
        
        let amount = coin::value(&coin);
        pool.total_liquidity = pool.total_liquidity + amount;
        pool.available_liquidity = pool.available_liquidity + amount;
        
        // 销毁存入的代币（实际应用中应转入池合约）
        coin::destroy_zero(coin);
        
        // 发出流动性提供事件
        event::emit(FlashLoanInitiated {
            borrower: tx_context::sender(ctx),
            asset: pool.asset,
            amount,
            fee: 0,
            timestamp: tx_context::epoch(ctx),
        });
    }
    
    /// @notice 发起闪电贷
    /// @param pool 闪电贷池对象
    /// @param amount 借款金额
    /// @param fee 手续费金额
    /// @param ctx 交易上下文
    public entry fun initiate_flash_loan(
        pool: &mut FlashLoanPool,
        amount: u64,
        fee: u64,
        ctx: &mut TxContext,
    ) {
        assert!(pool.is_active, EINVALID_RECEIVER);
        assert!(amount <= pool.available_liquidity, EINSUFFICIENT_BALANCE);
        
        // 计算手续费（金额 * 费率）
        let calculated_fee = (amount * FLASH_LOAN_FEE_RATE) / PRECISION;
        assert!(fee >= calculated_fee, EINSUFFICIENT_FEE);
        
        // 更新池状态
        pool.available_liquidity = pool.available_liquidity - amount;
        pool.total_fees_earned = pool.total_fees_earned + fee;
        
        // 创建闪电贷记录
        let record = FlashLoanRecord {
            id: object::new(ctx),
            borrower: tx_context::sender(ctx),
            asset: pool.asset,
            amount,
            fee,
            initiation_timestamp: tx_context::epoch(ctx),
            repaid: false,
        };
        
        transfer::transfer(record, tx_context::sender(ctx));
        
        // 发出闪电贷发起事件
        event::emit(FlashLoanInitiated {
            borrower: tx_context::sender(ctx),
            asset: pool.asset,
            amount,
            fee,
            timestamp: tx_context::epoch(ctx),
        });
    }
    
    /// @notice 归还闪电贷
    /// @param pool 闪电贷池对象
    /// @param record 闪电贷记录对象
    /// @param coin 归还的代币（本金+手续费）
    public entry fun repay_flash_loan(
        pool: &mut FlashLoanPool,
        record: &mut FlashLoanRecord,
        coin: Coin<address>,
        ctx: &mut TxContext,
    ) {
        assert!(!record.repaid, EFLASH_LOAN_NOT_REPAID);
        assert!(record.borrower == tx_context::sender(ctx), EINVALID_RECEIVER);
        
        let repaid_amount = coin::value(&coin);
        let total_due = record.amount + record.fee;
        assert!(repaid_amount >= total_due, EINSUFFICIENT_BALANCE);
        
        // 更新池状态
        pool.available_liquidity = pool.available_liquidity + record.amount;
        
        // 标记记录为已归还
        record.repaid = true;
        
        // 销毁归还的代币（实际应用中应转入池合约）
        coin::destroy_zero(coin);
        
        // 发出闪电贷归还事件
        event::emit(FlashLoanRepaid {
            borrower: record.borrower,
            asset: record.asset,
            amount: record.amount,
            fee: record.fee,
            timestamp: tx_context::epoch(ctx),
        });
    }
    
    // ============ 视图函数 ============
    
    /// @notice 获取池信息
    public fun get_pool_info(pool: &FlashLoanPool): (address, u64, u64, u64, bool) {
        (
            pool.asset,
            pool.total_liquidity,
            pool.available_liquidity,
            pool.total_fees_earned,
            pool.is_active,
        )
    }
    
    /// @notice 获取闪电贷记录信息
    public fun get_loan_record(record: &FlashLoanRecord): (address, address, u64, u64, u64, bool) {
        (
            record.borrower,
            record.asset,
            record.amount,
            record.fee,
            record.initiation_timestamp,
            record.repaid,
        )
    }
}