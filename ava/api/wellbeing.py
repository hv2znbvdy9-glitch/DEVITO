"""REST API for AVA Wellbeing System."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

from ava.wellbeing.orchestrator import WellbeingOrchestrator
from ava.ai.optimizer import SmartOptimizer, PredictiveAutomation

logger = logging.getLogger(__name__)

# Initialize components
wellbeing: Optional[WellbeingOrchestrator] = None
optimizer: Optional[SmartOptimizer] = None
automation: Optional[PredictiveAutomation] = None

# Router
router = APIRouter(prefix="/api/wellbeing", tags=["wellbeing"])


# Pydantic models
class AchievementRequest(BaseModel):
    """Achievement tracking request."""

    title: str
    reward_points: int = 10


class AutomationRequest(BaseModel):
    """Automation creation request."""

    trigger: str
    action: str
    description: str


class MeditationRequest(BaseModel):
    """Meditation session request."""

    duration_minutes: int = 10


class ChillModeRequest(BaseModel):
    """Chill mode activation request."""

    hours: int = 2
    intensity: float = 0.5  # 0-1


class FeedbackRequest(BaseModel):
    """AI feedback request."""

    pillar: str
    feedback: str
    rating: int  # 1-5


class ShareTaskRequest(BaseModel):
    """Share task request."""

    task_id: str
    collaborators: List[str]


# Initialize
async def init_wellbeing_api():
    """Initialize wellbeing API components."""
    global wellbeing, optimizer, automation
    wellbeing = WellbeingOrchestrator()
    optimizer = SmartOptimizer()
    automation = PredictiveAutomation()
    logger.info("Wellbeing API initialized")


# 💚 GLÜCK (Happiness) Endpoints
@router.post("/happiness/unlock")
async def unlock_happiness(request: AchievementRequest) -> Dict[str, Any]:
    """Unlock happiness achievement."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.happiness.track_achievement(
        "default_user", request.title, request.reward_points
    )
    score = await wellbeing.happiness.get_happiness_score()

    return {
        "status": "achievement_unlocked",
        "achievement": request.title,
        "reward_points": request.reward_points,
        "happiness_score": score.score,
        "joy_streak": score.metadata.get("joy_streak", 0),
    }


@router.get("/happiness/score")
async def get_happiness_score() -> Dict[str, Any]:
    """Get current happiness score."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    score = await wellbeing.happiness.get_happiness_score()

    return {"pillar": "happiness", "score": score.score, "details": score.metadata}


# 🏥 GESUNDHEIT (Health) Endpoints
@router.post("/health/check")
async def run_health_check() -> Dict[str, Any]:
    """Run comprehensive health check."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.health.run_health_check()
    score = await wellbeing.health.get_health_score()

    return {
        "status": "health_check_complete",
        "health_score": score.score,
        "checks": score.metadata.get("system_checks", {}),
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/health/status")
async def get_health_status() -> Dict[str, Any]:
    """Get current health status."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    score = await wellbeing.health.get_health_score()

    return {
        "pillar": "health",
        "score": score.score,
        "system_checks": score.metadata.get("system_checks", {}),
    }


# 💕 LIEBE (Love/Community) Endpoints
@router.post("/community/connect")
async def connect_users(user_a: str, user_b: str) -> Dict[str, Any]:
    """Connect users for collaboration."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.community.connect_users(user_a, user_b)
    score = await wellbeing.community.get_love_score()

    return {
        "status": "users_connected",
        "connection": f"{user_a} <-> {user_b}",
        "love_score": score.score,
        "collaborations": score.metadata.get("collaborations_count", 0),
    }


@router.post("/community/share")
async def share_task(task_id: str, collaborators: List[str]) -> Dict[str, Any]:
    """Share a task with collaborators."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.community.share_task("default_user", task_id, collaborators)
    score = await wellbeing.community.get_love_score()

    return {
        "status": "task_shared",
        "task_id": task_id,
        "shared_with": collaborators,
        "love_score": score.score,
    }


# 🦅 FREIHEIT (Freedom) Endpoints
@router.post("/freedom/register-provider")
async def register_cloud_provider(provider: str, region: str = "us-east-1") -> Dict[str, Any]:
    """Register a cloud provider."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.freedom.register_cloud_provider(provider, region)
    score = await wellbeing.freedom.get_freedom_score()

    return {
        "status": "provider_registered",
        "provider": provider,
        "region": region,
        "freedom_score": score.score,
        "decentralization_level": score.metadata.get("decentralization_level", 0),
    }


@router.get("/freedom/score")
async def get_freedom_score() -> Dict[str, Any]:
    """Get current freedom score."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    score = await wellbeing.freedom.get_freedom_score()

    return {
        "pillar": "freedom",
        "score": score.score,
        "providers": score.metadata.get("registered_providers", []),
    }


# 🌴 FREIZEIT (Leisure/Automation) Endpoints
@router.post("/leisure/automate")
async def create_automation(request: AutomationRequest) -> Dict[str, Any]:
    """Create automated task."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.leisure.create_automation(request.description, request.trigger, request.action)
    score = await wellbeing.leisure.get_leisure_score()

    return {
        "status": "automation_created",
        "name": request.description,
        "trigger": request.trigger,
        "action": request.action,
        "leisure_score": score.score,
        "saved_time_hours": score.metadata.get("saved_time_hours", 0),
    }


@router.post("/leisure/execute")
async def execute_automations() -> Dict[str, Any]:
    """Execute all pending automations."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.leisure.execute_automations()
    score = await wellbeing.leisure.get_leisure_score()

    return {
        "status": "automations_executed",
        "leisure_score": score.score,
        "total_saved_time": score.metadata.get("saved_time_hours", 0),
    }


# 💰 GELD (Wealth) Endpoints
@router.post("/wealth/optimize")
async def optimize_resources() -> Dict[str, Any]:
    """Optimize resource allocation."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.wealth.optimize_resources()
    score = await wellbeing.wealth.get_wealth_score()

    return {
        "status": "resources_optimized",
        "wealth_score": score.score,
        "cumulative_savings": score.metadata.get("cumulative_savings", 0),
    }


@router.get("/wealth/score")
async def get_wealth_score() -> Dict[str, Any]:
    """Get current wealth score."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    score = await wellbeing.wealth.get_wealth_score()

    return {
        "pillar": "wealth",
        "score": score.score,
        "savings": score.metadata.get("cumulative_savings", 0),
    }


# 🧘 RUHE (Peace) Endpoints
@router.post("/peace/meditate")
async def start_meditation(request: MeditationRequest) -> Dict[str, Any]:
    """Start meditation session."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.peace.start_meditation(request.duration_minutes)
    score = await wellbeing.peace.get_peace_score()

    return {
        "status": "meditation_started",
        "duration_minutes": request.duration_minutes,
        "peace_score": score.score,
        "total_meditation": score.metadata.get("total_meditation_minutes", 0),
    }


@router.post("/peace/chill")
async def enable_chill_mode(request: ChillModeRequest) -> Dict[str, Any]:
    """Enable Zen Chill Mode."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.peace.enable_chill_mode(request.hours)
    score = await wellbeing.peace.get_peace_score()

    return {
        "status": "chill_mode_enabled",
        "duration_hours": request.hours,
        "intensity": request.intensity,
        "peace_score": score.score,
    }


@router.post("/peace/quiet-hours")
async def set_quiet_hours(start_hour: int, end_hour: int) -> Dict[str, Any]:
    """Set quiet hours (no system activity)."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    await wellbeing.peace.set_quiet_hours(start_hour, end_hour)
    score = await wellbeing.peace.get_peace_score()

    return {
        "status": "quiet_hours_set",
        "start_hour": start_hour,
        "end_hour": end_hour,
        "peace_score": score.score,
    }


# 🌟 Master Wellbeing Endpoints
@router.get("/overall")
async def get_overall_wellbeing() -> Dict[str, Any]:
    """Get overall wellbeing score across all pillars."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    result = await wellbeing.get_overall_wellbeing()

    return {
        "status": "success",
        "overall_score": result.get("overall_score", 0),
        "pillar_scores": result.get("pillar_scores", {}),
        "recommendation": result.get("recommendation", ""),
        "timestamp": datetime.now().isoformat(),
    }


@router.get("/history")
async def get_wellbeing_history(limit: int = 10) -> Dict[str, Any]:
    """Get wellbeing history."""
    if not wellbeing:
        raise HTTPException(status_code=500, detail="Wellbeing engine not initialized")

    history = wellbeing.wellbeing_history[-limit:]

    return {"status": "success", "history_length": len(history), "history": history}


# 🤖 AI Optimization Endpoints
@router.post("/ai/analyze-patterns")
async def analyze_patterns(data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze patterns in wellbeing data."""
    if not optimizer:
        raise HTTPException(status_code=500, detail="AI optimizer not initialized")

    result = await optimizer.analyze_patterns(data)

    return result


@router.get("/ai/predict-wellbeing")
async def predict_wellbeing_24h() -> Dict[str, Any]:
    """Predict wellbeing for next 24 hours."""
    if not wellbeing or not optimizer:
        raise HTTPException(status_code=500, detail="Engines not initialized")

    current = await wellbeing.get_overall_wellbeing()
    pillar_scores = current.get("pillar_scores", {})

    result = await optimizer.predict_wellbeing(pillar_scores)

    return result


@router.get("/ai/recommendations")
async def get_ai_recommendations() -> Dict[str, Any]:
    """Get AI-based personalized recommendations."""
    if not wellbeing or not optimizer:
        raise HTTPException(status_code=500, detail="Engines not initialized")

    current = await wellbeing.get_overall_wellbeing()
    pillar_scores = current.get("pillar_scores", {})

    recommendations = await optimizer.generate_recommendations(pillar_scores)

    return {
        "status": "success",
        "recommendations": recommendations,
        "timestamp": datetime.now().isoformat(),
    }


@router.post("/ai/feedback")
async def submit_ai_feedback(request: FeedbackRequest) -> Dict[str, Any]:
    """Submit feedback to improve AI."""
    if not optimizer:
        raise HTTPException(status_code=500, detail="AI optimizer not initialized")

    feedback = {
        "pillar": request.pillar,
        "feedback": request.feedback,
        "rating": request.rating,
        "timestamp": datetime.now().isoformat(),
    }

    result = await optimizer.learn_from_feedback(feedback)

    return result


@router.get("/ai/optimize-chill")
async def optimize_chill_mode() -> Dict[str, Any]:
    """Get AI-optimized Chill Mode settings."""
    if not wellbeing or not optimizer:
        raise HTTPException(status_code=500, detail="Engines not initialized")

    current = await wellbeing.get_overall_wellbeing()
    pillar_scores = current.get("pillar_scores", {})

    result = await optimizer.optimize_chill_mode(pillar_scores)

    return result


@router.post("/ai/predict-next-action")
async def predict_next_action(history: list) -> Dict[str, Any]:
    """Predict next user action based on history."""
    if not automation:
        raise HTTPException(status_code=500, detail="Predictive automation not initialized")

    result = await automation.predict_next_action(history)

    return result


# Health check
@router.get("/health")
async def wellbeing_health() -> Dict[str, str]:
    """Health check for wellbeing API."""
    status = "healthy" if wellbeing else "uninitialized"

    return {
        "status": status,
        "service": "AVA Wellbeing API",
        "timestamp": datetime.now().isoformat(),
    }
