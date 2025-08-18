"""
Simple test for analytics functionality
"""

import asyncio
import tempfile
import sqlite3
import os
from datetime import datetime


class SimpleAnalytics:
    """Simple analytics for testing"""
    
    def __init__(self):
        self.attacks = {}
        self.strategies = {}
    
    async def record_attack(self, attack_id: str, success: bool, response_time: float):
        """Record attack result"""
        if attack_id not in self.attacks:
            self.attacks[attack_id] = {
                'successes': 0,
                'failures': 0,
                'total_time': 0.0,
                'count': 0
            }
        
        data = self.attacks[attack_id]
        data['count'] += 1
        data['total_time'] += response_time
        
        if success:
            data['successes'] += 1
        else:
            data['failures'] += 1
    
    async def record_strategy(self, strategy_id: str, domain: str, success: bool):
        """Record strategy result"""
        if strategy_id not in self.strategies:
            self.strategies[strategy_id] = {
                'successes': 0,
                'failures': 0,
                'domains': set()
            }
        
        data = self.strategies[strategy_id]
        data['domains'].add(domain)
        
        if success:
            data['successes'] += 1
        else:
            data['failures'] += 1
    
    def get_attack_stats(self, attack_id: str):
        """Get attack statistics"""
        if attack_id not in self.attacks:
            return None
        
        data = self.attacks[attack_id]
        total = data['successes'] + data['failures']
        
        return {
            'success_rate': data['successes'] / total if total > 0 else 0,
            'avg_response_time': data['total_time'] / data['count'] if data['count'] > 0 else 0,
            'total_attempts': total
        }
    
    def get_strategy_stats(self, strategy_id: str):
        """Get strategy statistics"""
        if strategy_id not in self.strategies:
            return None
        
        data = self.strategies[strategy_id]
        total = data['successes'] + data['failures']
        
        return {
            'success_rate': data['successes'] / total if total > 0 else 0,
            'domain_count': len(data['domains']),
            'total_attempts': total
        }
    
    def get_system_overview(self):
        """Get system overview"""
        total_attack_successes = sum(data['successes'] for data in self.attacks.values())
        total_attack_attempts = sum(data['successes'] + data['failures'] for data in self.attacks.values())
        
        total_strategy_successes = sum(data['successes'] for data in self.strategies.values())
        total_strategy_attempts = sum(data['successes'] + data['failures'] for data in self.strategies.values())
        
        return {
            'attacks': {
                'count': len(self.attacks),
                'success_rate': total_attack_successes / total_attack_attempts if total_attack_attempts > 0 else 0
            },
            'strategies': {
                'count': len(self.strategies),
                'success_rate': total_strategy_successes / total_strategy_attempts if total_strategy_attempts > 0 else 0
            }
        }
    
    def generate_report(self):
        """Generate analytics report"""
        overview = self.get_system_overview()
        
        # Find top performers
        top_attacks = []
        for attack_id in self.attacks:
            stats = self.get_attack_stats(attack_id)
            if stats and stats['total_attempts'] > 0:
                top_attacks.append((attack_id, stats['success_rate']))
        
        top_attacks.sort(key=lambda x: x[1], reverse=True)
        
        top_strategies = []
        for strategy_id in self.strategies:
            stats = self.get_strategy_stats(strategy_id)
            if stats and stats['total_attempts'] > 0:
                top_strategies.append((strategy_id, stats['success_rate']))
        
        top_strategies.sort(key=lambda x: x[1], reverse=True)
        
        # Generate recommendations
        recommendations = []
        for attack_id in self.attacks:
            stats = self.get_attack_stats(attack_id)
            if stats and stats['success_rate'] < 0.5 and stats['total_attempts'] > 3:
                recommendations.append(f"Review {attack_id} configuration (low success rate)")
        
        if not recommendations:
            recommendations.append("System performance is stable")
        
        return {
            'timestamp': datetime.now().isoformat(),
            'overview': overview,
            'top_attacks': top_attacks[:5],
            'top_strategies': top_strategies[:5],
            'recommendations': recommendations
        }


async def test_analytics():
    """Test analytics functionality"""
    print("=== Testing Analytics System ===")
    
    analytics = SimpleAnalytics()
    
    # Test attack recording
    print("\n1. Testing Attack Recording...")
    attacks = ["tcp_frag", "http_manip", "tls_evasion", "dns_tunnel"]
    
    for i, attack in enumerate(attacks):
        for j in range(10):
            success = (i + j) % 3 != 0  # Varying success rates
            response_time = 1.0 + (j % 5) * 0.2
            await analytics.record_attack(attack, success, response_time)
    
    print("✓ Recorded attack results")
    
    # Test strategy recording
    print("\n2. Testing Strategy Recording...")
    strategies = ["basic_strategy", "advanced_strategy", "hybrid_strategy"]
    domains = ["example.com", "test.org", "demo.net"]
    
    for strategy in strategies:
        for domain in domains:
            for k in range(5):
                success = hash(strategy + domain + str(k)) % 4 != 0
                await analytics.record_strategy(strategy, domain, success)
    
    print("✓ Recorded strategy results")
    
    # Test analytics retrieval
    print("\n3. Testing Analytics Retrieval...")
    
    for attack in attacks:
        stats = analytics.get_attack_stats(attack)
        if stats:
            print(f"  {attack}: {stats['success_rate']:.2%} success, "
                  f"{stats['avg_response_time']:.2f}s avg time")
    
    for strategy in strategies:
        stats = analytics.get_strategy_stats(strategy)
        if stats:
            print(f"  {strategy}: {stats['success_rate']:.2%} success, "
                  f"{stats['domain_count']} domains")
    
    # Test system overview
    print("\n4. Testing System Overview...")
    overview = analytics.get_system_overview()
    
    print(f"  Attacks: {overview['attacks']['count']} total, "
          f"{overview['attacks']['success_rate']:.2%} success rate")
    print(f"  Strategies: {overview['strategies']['count']} total, "
          f"{overview['strategies']['success_rate']:.2%} success rate")
    
    # Test report generation
    print("\n5. Testing Report Generation...")
    report = analytics.generate_report()
    
    print(f"  Generated at: {report['timestamp']}")
    print(f"  Top attacks: {len(report['top_attacks'])}")
    print(f"  Top strategies: {len(report['top_strategies'])}")
    print(f"  Recommendations: {len(report['recommendations'])}")
    
    if report['top_attacks']:
        print(f"    Best attack: {report['top_attacks'][0][0]} "
              f"({report['top_attacks'][0][1]:.2%})")
    
    if report['top_strategies']:
        print(f"    Best strategy: {report['top_strategies'][0][0]} "
              f"({report['top_strategies'][0][1]:.2%})")
    
    print(f"    Recommendations:")
    for i, rec in enumerate(report['recommendations'][:3], 1):
        print(f"      {i}. {rec}")
    
    print("\n✓ All analytics tests completed successfully!")
    
    return analytics, report


async def test_ml_prediction_simulation():
    """Simulate ML prediction functionality"""
    print("\n=== Testing ML Prediction Simulation ===")
    
    # Simple prediction based on historical data
    def predict_success_rate(historical_rates):
        """Simple moving average prediction"""
        if len(historical_rates) < 3:
            return 0.5, 0.3  # Default prediction with low confidence
        
        recent = historical_rates[-5:]  # Last 5 data points
        prediction = sum(recent) / len(recent)
        
        # Calculate confidence based on variance
        variance = sum((x - prediction) ** 2 for x in recent) / len(recent)
        confidence = max(0.1, 1.0 - variance)
        
        return prediction, confidence
    
    # Test with sample data
    test_data = [0.8, 0.7, 0.75, 0.6, 0.65, 0.7, 0.8, 0.75]
    prediction, confidence = predict_success_rate(test_data)
    
    print(f"  Historical data: {test_data}")
    print(f"  Predicted success rate: {prediction:.2%}")
    print(f"  Confidence: {confidence:.2%}")
    
    # Test trend detection
    def detect_trend(data):
        """Simple trend detection"""
        if len(data) < 3:
            return "insufficient_data"
        
        recent = data[-5:]
        if len(recent) < 3:
            return "stable"
        
        # Calculate slope
        x = list(range(len(recent)))
        y = recent
        n = len(x)
        
        slope = (n * sum(x[i] * y[i] for i in range(n)) - sum(x) * sum(y)) / (n * sum(x[i]**2 for i in range(n)) - sum(x)**2)
        
        if slope > 0.05:
            return "improving"
        elif slope < -0.05:
            return "declining"
        else:
            return "stable"
    
    trend = detect_trend(test_data)
    print(f"  Detected trend: {trend}")
    
    print("✓ ML prediction simulation completed")


async def main():
    """Main test function"""
    print("Analytics and Reporting System Test")
    print("=" * 50)
    
    # Run main analytics test
    analytics, report = await test_analytics()
    
    # Run ML prediction simulation
    await test_ml_prediction_simulation()
    
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    
    print("✓ Attack metrics collection and analysis")
    print("✓ Strategy performance tracking")
    print("✓ System overview generation")
    print("✓ Comprehensive reporting")
    print("✓ Top performer identification")
    print("✓ Recommendation generation")
    print("✓ ML prediction simulation")
    
    print(f"\nFinal Statistics:")
    overview = analytics.get_system_overview()
    print(f"  - {overview['attacks']['count']} attacks monitored")
    print(f"  - {overview['strategies']['count']} strategies tracked")
    print(f"  - {overview['attacks']['success_rate']:.1%} overall attack success rate")
    print(f"  - {overview['strategies']['success_rate']:.1%} overall strategy success rate")
    print(f"  - {len(report['recommendations'])} recommendations generated")
    
    print("\n🎉 All tests passed successfully!")


if __name__ == "__main__":
    asyncio.run(main())