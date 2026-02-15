#!/usr/bin/env python
"""Integration test and demo for AVA Wellbeing System."""

import asyncio
import sys
from datetime import datetime

# Test imports
try:
    from ava.wellbeing.orchestrator import WellbeingOrchestrator
    from ava.ai.optimizer import SmartOptimizer, PredictiveAutomation
    from ava.dashboard.config import WellbeingDashboard
    from ava.monitoring.metrics import WellbeingMetrics
    from ava.api.wellbeing import init_wellbeing_api
    print("✅ All imports successful!")
except Exception as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)


async def demo_wellbeing_system():
    """Demo the complete wellbeing system."""
    
    print("\n" + "="*60)
    print("🌟 AVA Wellbeing System - Integration Demo")
    print("="*60 + "\n")
    
    # Initialize components
    print("📋 Initializing components...")
    orchestrator = WellbeingOrchestrator()
    optimizer = SmartOptimizer()
    automation = PredictiveAutomation()
    metrics = WellbeingMetrics()
    dashboard_config = WellbeingDashboard.get_dashboard_config()
    
    print("✅ Components initialized!\n")
    
    # Demo 1: Track some achievements
    print("💚 HAPPINESS Engine - Tracking achievements...")
    await orchestrator.happiness.track_achievement("user_1", "Meditation Complete", 15)
    await orchestrator.happiness.track_achievement("user_1", "Task Completed", 10)
    happiness_score = await orchestrator.happiness.get_happiness_score()
    print(f"   Score: {happiness_score.score:.1f}/100")
    metrics.record_pillar_score("happiness", happiness_score.score)
    
    # Demo 2: Health check
    print("\n🏥 HEALTH Engine - Running health check...")
    await orchestrator.health.run_health_check()
    health_score = await orchestrator.health.get_health_score()
    print(f"   Score: {health_score.score:.1f}/100")
    metrics.record_pillar_score("health", health_score.score)
    
    # Demo 3: Community connection
    print("\n💕 LOVE Engine - Connecting users...")
    await orchestrator.community.connect_users("Alice", "Bob")
    love_score = await orchestrator.community.get_love_score()
    print(f"   Score: {love_score.score:.1f}/100")
    metrics.record_pillar_score("love", love_score.score)
    
    # Demo 4: Freedom registration
    print("\n🦅 FREEDOM Engine - Registering cloud providers...")
    for provider in ["AWS", "Azure", "GCP"]:
        await orchestrator.freedom.register_cloud_provider(provider, "us-east-1")
        metrics.record_cloud_provider(provider)
    freedom_score = await orchestrator.freedom.get_freedom_score()
    print(f"   Score: {freedom_score.score:.1f}/100")
    metrics.record_pillar_score("freedom", freedom_score.score)
    
    # Demo 5: Automation
    print("\n🌴 LEISURE Engine - Creating automations...")
    await orchestrator.leisure.create_automation("daily_report", "daily", "send_report")
    metrics.record_automation()
    leisure_score = await orchestrator.leisure.get_leisure_score()
    print(f"   Score: {leisure_score.score:.1f}/100")
    metrics.record_pillar_score("leisure", leisure_score.score)
    
    # Demo 6: Cost optimization
    print("\n💰 WEALTH Engine - Optimizing resources...")
    await orchestrator.wealth.optimize_resources()
    wealth_score = await orchestrator.wealth.get_wealth_score()
    print(f"   Score: {wealth_score.score:.1f}/100")
    metrics.record_pillar_score("wealth", wealth_score.score)
    
    # Demo 7: Peace & meditation
    print("\n🧘 PEACE Engine - Starting meditation...")
    await orchestrator.peace.start_meditation(10)
    metrics.record_meditation(10)
    peace_score = await orchestrator.peace.get_peace_score()
    print(f"   Score: {peace_score.score:.1f}/100")
    metrics.record_pillar_score("peace", peace_score.score)
    
    # Master orchestrator
    print("\n🌟 MASTER Orchestrator - Calculating overall wellbeing...")
    result = await orchestrator.get_overall_wellbeing()
    overall_score = result["overall_wellbeing"]
    metrics.record_overall_score(overall_score)
    print(f"   Overall Score: {overall_score:.1f}/100")
    print(f"   Recommendation: {result['recommendation']}")
    
    # AI Optimizer
    print("\n🤖 AI OPTIMIZER - Analyzing patterns...")
    patterns = await optimizer.analyze_patterns({"task_completion_rate": 0.85})
    print(f"   Patterns found: {patterns['insights']}")
    
    # Predictions
    print("\n🔮 AI PREDICTIONS - Predicting next 24h...")
    pillar_scores = result["pillars"]
    predictions = await optimizer.predict_wellbeing(pillar_scores)
    print(f"   Confidence: {predictions['confidence']*100:.0f}%")
    
    # Recommendations
    print("\n💡 AI RECOMMENDATIONS - Generating recommendations...")
    recommendations = await optimizer.generate_recommendations(pillar_scores)
    for pillar, recs in recommendations.items():
        if recs:
            print(f"   {pillar}: {recs[0]}")
            metrics.record_recommendation(pillar)
    
    # Chill mode optimization
    print("\n✨ CHILL MODE - Optimizing zen settings...")
    chill_result = await optimizer.optimize_chill_mode(pillar_scores)
    metrics.record_chill_mode(
        chill_result['chill_mode'].get('duration_hours', 2),
        chill_result['chill_mode'].get('intensity', 0.5)
    )
    print(f"   Chill Mode Enabled: {chill_result['chill_mode']['enabled']}")
    print(f"   Intensity: {chill_result['chill_mode']['intensity']:.1f}")
    
    # Dashboard info
    print("\n📊 DASHBOARD CONFIG - Available pillars...")
    for pillar_name in dashboard_config["pillars"].keys():
        pillar_config = dashboard_config["pillars"][pillar_name]
        print(f"   {pillar_config['icon']} {pillar_name.upper()}: {pillar_config['color']}")
    
    # Metrics summary
    print("\n📈 METRICS SUMMARY...")
    summary = metrics.get_wellbeing_metrics_summary()
    print(f"   Overall Average: {summary['overall_average_score']:.1f}/100")
    print(f"   Trend: {summary['trend']}")
    print(f"   Total Recommendations: {summary['metrics']['recommendations_generated']}")
    print(f"   Total Predictions: {summary['metrics']['ai_predictions_made']}")
    print(f"   Meditation Sessions: {summary['metrics']['meditation_sessions']}")
    print(f"   Automations Created: {summary['metrics']['automations_created']}")
    print(f"   Cloud Providers: {summary['metrics']['cloud_providers_registered']}")
    
    print("\n" + "="*60)
    print("✅ Integration demo completed successfully!")
    print("="*60)
    
    print("\n📝 Next steps:")
    print("   1. Start the API server: python -m ava.server")
    print("   2. Run tests: pytest tests/test_wellbeing.py -v")
    print("   3. Access API: http://localhost:8000/docs")
    print("   4. Deploy with: docker-compose up")
    print("\n")


if __name__ == "__main__":
    try:
        asyncio.run(demo_wellbeing_system())
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
