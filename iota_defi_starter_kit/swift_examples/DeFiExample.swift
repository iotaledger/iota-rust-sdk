//
//  DeFiExample.swift
//  IOTADeFiExample
//
//  IOTA Move DeFi Starter Kit - Swift SDK示例
//  演示如何使用Swift与DeFi智能合约交互
//

import Foundation
import Combine

// 注意: 实际项目需要导入Sui Swift SDK
// 这里使用模拟实现

// MARK: - 数据模型

/// 借贷池状态
struct PoolState: Codable {
    let totalSupply: UInt64
    let totalBorrowed: UInt64
    let utilizationRate: Double
    let currentInterestRate: Double
    let reserveFactor: Double
    let lastUpdateTime: UInt64
    
    var formattedUtilizationRate: String {
        return String(format: "%.2f%%", utilizationRate * 100)
    }
    
    var formattedInterestRate: String {
        return String(format: "%.2f%%", currentInterestRate * 100)
    }
}

/// 用户仓位信息
struct UserPosition: Codable {
    let suppliedAmount: UInt64
    let borrowedAmount: UInt64
    let collateralValue: UInt64
    let borrowLimit: UInt64
    let healthFactor: Double
    let isLiquidatable: Bool
    
    var formattedHealthFactor: String {
        return String(format: "%.2f", healthFactor)
    }
}

/// DeFi事件
enum DeFiEvent: String, Codable {
    case deposit = "DepositEvent"
    case borrow = "BorrowEvent"
    case repay = "RepayEvent"
    case withdraw = "WithdrawEvent"
    case liquidation = "LiquidationEvent"
    case flashLoan = "FlashLoanEvent"
    
    var description: String {
        switch self {
        case .deposit: return "存款事件"
        case .borrow: return "借款事件"
        case .repay: return "还款事件"
        case .withdraw: return "取款事件"
        case .liquidation: return "清算事件"
        case .flashLoan: return "闪电贷事件"
        }
    }
    
    var emoji: String {
        switch self {
        case .deposit: return "💰"
        case .borrow: return "🏦"
        case .repay: return "↩️"
        case .withdraw: return "💸"
        case .liquidation: return "⚠️"
        case .flashLoan: return "⚡"
        }
    }
}

/// 事件数据
struct EventData: Codable {
    let type: DeFiEvent
    let timestamp: UInt64
    let data: [String: String]
}

// MARK: - DeFi客户端

/// DeFi客户端协议
protocol DeFiClientProtocol {
    func queryPoolState(poolId: String) async throws -> PoolState
    func getUserPosition(userAddress: String, poolId: String) async throws -> UserPosition
    func supplyAssets(poolId: String, assetId: String, amount: UInt64) async throws -> String
    func borrowAssets(poolId: String, amount: UInt64) async throws -> String
    func executeFlashLoan(poolId: String, amount: UInt64, callbackData: Data) async throws -> String
    func monitorEvents() -> AnyPublisher<EventData, Never>
}

/// 模拟DeFi客户端
class MockDeFiClient: DeFiClientProtocol {
    
    private let config: [String: String]
    private var eventSubject = PassthroughSubject<EventData, Never>()
    
    init(config: [String: String]) {
        self.config = config
        print("初始化模拟DeFi客户端")
    }
    
    func queryPoolState(poolId: String) async throws -> PoolState {
        print("查询借贷池状态: \(poolId)")
        
        // 模拟延迟
        try await Task.sleep(nanoseconds: 500_000_000)
        
        // 返回模拟数据
        return PoolState(
            totalSupply: 1_000_000_000,
            totalBorrowed: 450_000_000,
            utilizationRate: 0.45,
            currentInterestRate: 0.085,
            reserveFactor: 0.1,
            lastUpdateTime: UInt64(Date().timeIntervalSince1970)
        )
    }
    
    func getUserPosition(userAddress: String, poolId: String) async throws -> UserPosition {
        print("查询用户仓位: \(userAddress), pool: \(poolId)")
        
        try await Task.sleep(nanoseconds: 300_000_000)
        
        // 随机生成健康因子 (1.0-3.0)
        let healthFactor = 1.0 + Double.random(in: 0...2.0)
        
        return UserPosition(
            suppliedAmount: 100_000,
            borrowedAmount: 40_000,
            collateralValue: 150_000,
            borrowLimit: 75_000,
            healthFactor: healthFactor,
            isLiquidatable: healthFactor < 1.0
        )
    }
    
    func supplyAssets(poolId: String, assetId: String, amount: UInt64) async throws -> String {
        print("存入资产: pool=\(poolId), asset=\(assetId), amount=\(amount)")
        
        try await Task.sleep(nanoseconds: 1_000_000_000)
        
        // 模拟事件发射
        let event = EventData(
            type: .deposit,
            timestamp: UInt64(Date().timeIntervalSince1970),
            data: [
                "pool": poolId,
                "asset": assetId,
                "amount": "\(amount)",
                "transaction": "mock_tx_0x123456"
            ]
        )
        eventSubject.send(event)
        
        return "mock_transaction_digest_0x123456"
    }
    
    func borrowAssets(poolId: String, amount: UInt64) async throws -> String {
        print("借款: pool=\(poolId), amount=\(amount)")
        
        // 检查健康因子
        let position = try await getUserPosition(userAddress: "mock_user", poolId: poolId)
        guard position.healthFactor >= 1.0 else {
            throw NSError(domain: "DeFiError", code: 1, userInfo: [NSLocalizedDescriptionKey: "健康因子不足: \(position.formattedHealthFactor)"])
        }
        
        try await Task.sleep(nanoseconds: 1_000_000_000)
        
        let event = EventData(
            type: .borrow,
            timestamp: UInt64(Date().timeIntervalSince1970),
            data: [
                "pool": poolId,
                "amount": "\(amount)",
                "interest_rate": "8.5%",
                "transaction": "mock_tx_0x789012"
            ]
        )
        eventSubject.send(event)
        
        return "mock_transaction_digest_0x789012"
    }
    
    func executeFlashLoan(poolId: String, amount: UInt64, callbackData: Data) async throws -> String {
        print("执行闪电贷: pool=\(poolId), amount=\(amount)")
        
        try await Task.sleep(nanoseconds: 2_000_000_000)
        
        // 模拟闪电贷流程
        print("1. 借出 \(amount) 资产")
        print("2. 执行回调操作")
        print("3. 归还资产 + 手续费 (0.09%)")
        
        let event = EventData(
            type: .flashLoan,
            timestamp: UInt64(Date().timeIntervalSince1970),
            data: [
                "pool": poolId,
                "amount": "\(amount)",
                "fee": "\(Double(amount) * 0.0009)",
                "transaction": "mock_tx_0x345678"
            ]
        )
        eventSubject.send(event)
        
        return "mock_flash_loan_digest_0x345678"
    }
    
    func monitorEvents() -> AnyPublisher<EventData, Never> {
        // 模拟定期事件生成
        Task {
            let eventTypes: [DeFiEvent] = [.deposit, .borrow, .repay, .withdraw, .liquidation, .flashLoan]
            
            for eventType in eventTypes {
                try await Task.sleep(nanoseconds: 3_000_000_000)
                
                let event = EventData(
                    type: eventType,
                    timestamp: UInt64(Date().timeIntervalSince1970),
                    data: [
                        "mock": "true",
                        "sequence": "\(Int.random(in: 1...1000))"
                    ]
                )
                eventSubject.send(event)
            }
        }
        
        return eventSubject.eraseToAnyPublisher()
    }
    
    func startSimulatedEvents() {
        Task {
            while true {
                try await Task.sleep(nanoseconds: 5_000_000_000)
                
                // 随机生成事件
                let eventTypes: [DeFiEvent] = [.deposit, .borrow, .repay]
                if let randomEvent = eventTypes.randomElement() {
                    let event = EventData(
                        type: randomEvent,
                        timestamp: UInt64(Date().timeIntervalSince1970),
                        data: ["simulated": "true"]
                    )
                    eventSubject.send(event)
                }
            }
        }
    }
}

// MARK: - 风险管理

/// 风险评估器
class RiskAssessor {
    
    static func assessPoolRisk(poolState: PoolState) -> (level: String, recommendations: [String]) {
        var riskLevel = "低"
        var recommendations: [String] = []
        
        // 基于利用率评估
        if poolState.utilizationRate > 0.8 {
            riskLevel = "高"
            recommendations.append("⚠️ 利用率过高 (\(poolState.formattedUtilizationRate))，建议增加流动性")
        } else if poolState.utilizationRate > 0.6 {
            riskLevel = "中"
            recommendations.append("📊 利用率适中 (\(poolState.formattedUtilizationRate))，建议持续监控")
        } else {
            riskLevel = "低"
            recommendations.append("✅ 利用率安全 (\(poolState.formattedUtilizationRate))")
        }
        
        // 基于利率评估
        if poolState.currentInterestRate > 0.15 {
            riskLevel = "高"
            recommendations.append("📈 利率过高 (\(poolState.formattedInterestRate))，可能影响借款需求")
        } else if poolState.currentInterestRate > 0.1 {
            recommendations.append("📈 利率较高 (\(poolState.formattedInterestRate))，借款人成本增加")
        }
        
        return (riskLevel, recommendations)
    }
    
    static func assessPositionRisk(position: UserPosition) -> (level: String, warnings: [String]) {
        var riskLevel = "低"
        var warnings: [String] = []
        
        if position.isLiquidatable {
            riskLevel = "危险"
            warnings.append("❌ 仓位可被清算！健康因子: \(position.formattedHealthFactor)")
        } else if position.healthFactor < 1.5 {
            riskLevel = "高"
            warnings.append("⚠️ 健康因子偏低 (\(position.formattedHealthFactor))，接近清算阈值")
        } else if position.healthFactor < 2.0 {
            riskLevel = "中"
            warnings.append("📊 健康因子适中 (\(position.formattedHealthFactor))")
        } else {
            riskLevel = "低"
            warnings.append("✅ 健康因子安全 (\(position.formattedHealthFactor))")
        }
        
        // 借款额度使用率
        let borrowUsage = Double(position.borrowedAmount) / Double(position.borrowLimit)
        if borrowUsage > 0.9 {
            warnings.append("📈 借款额度使用率过高 (\(String(format: "%.1f%%", borrowUsage * 100)))")
        }
        
        return (riskLevel, warnings)
    }
}

// MARK: - 工具函数

extension Date {
    func formattedTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: self)
    }
}

extension UInt64 {
    func formattedAmount() -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        return formatter.string(from: NSNumber(value: self)) ?? "\(self)"
    }
}

// MARK: - 主程序

@main
struct IOTADeFiExample {
    
    static func main() async {
        print("🚀 IOTA Move DeFi Starter Kit - Swift示例")
        print("=" * 60)
        
        // 配置
        let config = [
            "lending_pool_package_id": "0xYOUR_LENDING_POOL_PACKAGE_ID",
            "flash_loan_package_id": "0xYOUR_FLASH_LOAN_PACKAGE_ID",
            "testnet_rpc": "https://fullnode.testnet.sui.io:443"
        ]
        
        // 初始化客户端
        let client = MockDeFiClient(config: config)
        
        // 启动模拟事件
        client.startSimulatedEvents()
        
        do {
            // 示例1: 查询池状态
            print("\n📊 示例1: 查询借贷池状态")
            let poolState = try await client.queryPoolState(poolId: "0xmock_pool")
            
            print("总供应量: \(poolState.totalSupply.formattedAmount())")
            print("总借款量: \(poolState.totalBorrowed.formattedAmount())")
            print("利用率: \(poolState.formattedUtilizationRate)")
            print("当前利率: \(poolState.formattedInterestRate)")
            print("储备因子: \(String(format: "%.1f%%", poolState.reserveFactor * 100))")
            
            // 风险评估
            let poolRisk = RiskAssessor.assessPoolRisk(poolState: poolState)
            print("池风险等级: \(poolRisk.level)")
            for recommendation in poolRisk.recommendations {
                print("  \(recommendation)")
            }
            
            // 示例2: 查询用户仓位
            print("\n👤 示例2: 查询用户仓位")
            let userPosition = try await client.getUserPosition(
                userAddress: "0xmock_user_address",
                poolId: "0xmock_pool"
            )
            
            print("存入金额: \(userPosition.suppliedAmount.formattedAmount())")
            print("借款金额: \(userPosition.borrowedAmount.formattedAmount())")
            print("抵押价值: \(userPosition.collateralValue.formattedAmount())")
            print("借款限额: \(userPosition.borrowLimit.formattedAmount())")
            print("健康因子: \(userPosition.formattedHealthFactor)")
            print("可清算: \(userPosition.isLiquidatable ? "是" : "否")")
            
            // 仓位风险评估
            let positionRisk = RiskAssessor.assessPositionRisk(position: userPosition)
            print("仓位风险等级: \(positionRisk.level)")
            for warning in positionRisk.warnings {
                print("  \(warning)")
            }
            
            // 示例3: 存款操作
            print("\n💰 示例3: 存款操作")
            let supplyTx = try await client.supplyAssets(
                poolId: "0xmock_pool",
                assetId: "0xmock_asset",
                amount: 1000
            )
            print("存款交易提交成功: \(supplyTx)")
            
            // 示例4: 借款操作（仅在健康因子安全时）
            print("\n🏦 示例4: 借款操作")
            if userPosition.healthFactor >= 1.0 {
                let borrowTx = try await client.borrowAssets(
                    poolId: "0xmock_pool",
                    amount: 500
                )
                print("借款交易提交成功: \(borrowTx)")
            } else {
                print("跳过借款: 健康因子不足 (\(userPosition.formattedHealthFactor))")
            }
            
            // 示例5: 闪电贷
            print("\n⚡ 示例5: 闪电贷操作")
            let flashLoanTx = try await client.executeFlashLoan(
                poolId: "0xmock_flash_loan_pool",
                amount: 10000,
                callbackData: "arbitrage_operation".data(using: .utf8)!
            )
            print("闪电贷交易提交成功: \(flashLoanTx)")
            
            // 示例6: 事件监控
            print("\n👁️  示例6: 事件监控")
            print("开始监控DeFi事件...")
            
            let eventSubscription = client.monitorEvents()
                .sink { event in
                    print("\n\(event.emoji) [\(Date(timeIntervalSince1970: TimeInterval(event.timestamp)).formattedTimestamp())]")
                    print("事件类型: \(event.description)")
                    print("事件数据: \(event.data)")
                    
                    // 特殊事件处理
                    if event.type == .liquidation {
                        print("⚠️  警告: 检测到清算事件！")
                    } else if event.type == .flashLoan {
                        print("⚡ 闪电贷执行完成")
                    }
                }
            
            // 保持程序运行以接收事件
            print("\n程序运行中，等待事件...")
            print("按Ctrl+C退出")
            
            // 模拟运行一段时间
            try await Task.sleep(nanoseconds: 15_000_000_000)
            
            // 取消订阅
            eventSubscription.cancel()
            
            print("\n" + "=" * 60)
            print("✅ 所有示例执行完成")
            
        } catch {
            print("❌ 错误: \(error.localizedDescription)")
        }
        
        print("\n💡 下一步:")
        print("1. 安装Sui Swift SDK")
        print("2. 部署实际合约并更新配置")
        print("3. 配置私钥和网络连接")
        print("4. 运行完整测试")
    }
}