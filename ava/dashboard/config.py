"""AVA Wellbeing Dashboard Configuration."""

from dataclasses import dataclass
from typing import Dict, List, Any
from enum import Enum


class PillarColor(str, Enum):
    """Pillar color scheme."""
    HAPPINESS = "#FFD700"  # Gold
    HEALTH = "#00D084"     # Emerald
    LOVE = "#FF6B9D"       # Pink
    FREEDOM = "#4A90E2"    # Blue
    LEISURE = "#7ED321"    # Green
    WEALTH = "#50E3C2"     # Teal
    PEACE = "#8B7FD0"      # Purple


@dataclass
class PillarConfig:
    """Configuration for a wellbeing pillar."""
    name: str
    icon: str
    color: str
    description: str
    short_name: str


class WellbeingDashboard:
    """🌟 AVA Wellbeing Dashboard Configuration."""
    
    # Pillar configurations
    PILLARS: Dict[str, PillarConfig] = {
        "happiness": PillarConfig(
            name="Happiness",
            icon="💚",
            color=PillarColor.HAPPINESS,
            description="Track joy, achievements, and motivation",
            short_name="GLÜCK"
        ),
        "health": PillarConfig(
            name="Health",
            icon="🏥",
            color=PillarColor.HEALTH,
            description="System health and vitality checks",
            short_name="GESUNDHEIT"
        ),
        "love": PillarConfig(
            name="Love & Community",
            icon="💕",
            color=PillarColor.LOVE,
            description="Connections, collaborations, relationships",
            short_name="LIEBE"
        ),
        "freedom": PillarConfig(
            name="Freedom",
            icon="🦅",
            color=PillarColor.FREEDOM,
            description="Multi-cloud, decentralization, independence",
            short_name="FREIHEIT"
        ),
        "leisure": PillarConfig(
            name="Leisure & Automation",
            icon="🌴",
            color=PillarColor.LEISURE,
            description="Saved time, automations, smart workflows",
            short_name="FREIZEIT"
        ),
        "wealth": PillarConfig(
            name="Wealth & Optimization",
            icon="💰",
            color=PillarColor.WEALTH,
            description="Cost optimization, resource efficiency",
            short_name="GELD"
        ),
        "peace": PillarConfig(
            name="Peace & Rest",
            icon="🧘",
            color=PillarColor.PEACE,
            description="Meditation, chill mode, quiet hours",
            short_name="RUHE"
        ),
    }
    
    # UI Layout Configuration
    LAYOUT = {
        "theme": "zen",  # zen, dark, light, cyberpunk
        "layout": "radial",  # radial, linear, grid
        "animation_speed": "smooth",  # fast, smooth, slow
        "show_metrics": True,
        "show_recommendations": True,
        "show_history": True,
    }
    
    # Visualization Configuration
    VISUALIZATION = {
        "main_display": "circular_mandala",  # Main 7-pillar display
        "pillar_display": "progress_arc",
        "history_display": "sparkline",
        "recommendation_display": "card",
        "chill_mode_display": "zen",
    }
    
    # Color schemes
    COLOR_SCHEMES = {
        "zen": {
            "background": "#0F1419",
            "text": "#E8E8E8",
            "accent": "#62F0E4",
            "success": "#00D084",
            "warning": "#FFB627",
            "error": "#FF6B6B",
        },
        "dark": {
            "background": "#1E1E2E",
            "text": "#FFFFFF",
            "accent": "#8B7FD0",
            "success": "#50FA7B",
            "warning": "#FFB86C",
            "error": "#FF79C6",
        },
        "light": {
            "background": "#FFFFFF",
            "text": "#1E1E2E",
            "accent": "#4A90E2",
            "success": "#00D084",
            "warning": "#FFB627",
            "error": "#FF6B6B",
        },
    }
    
    # Animation presets
    ANIMATIONS = {
        "pulse": {
            "duration": 2000,
            "easing": "ease-in-out",
        },
        "float": {
            "duration": 3000,
            "easing": "ease-in-out",
        },
        "glow": {
            "duration": 1500,
            "easing": "ease-in-out",
        },
    }
    
    # Chill mode settings
    CHILL_MODE = {
        "light": {
            "opacity": 0.8,
            "saturation": 70,
            "brightness": 80,
            "animations": ["float"],
            "sounds": "on",
            "notifications": "muted",
        },
        "medium": {
            "opacity": 0.6,
            "saturation": 30,
            "brightness": 60,
            "animations": ["float"],
            "sounds": "off",
            "notifications": "silent",
        },
        "full": {
            "opacity": 0.4,
            "saturation": 0,
            "brightness": 40,
            "animations": ["float"],
            "sounds": "off",
            "notifications": "off",
            "show_only_meditation": True,
        },
    }
    
    @classmethod
    def get_dashboard_config(cls) -> Dict[str, Any]:
        """Get complete dashboard configuration."""
        return {
            "pillars": {
                name: {
                    "name": config.name,
                    "icon": config.icon,
                    "color": config.color,
                    "description": config.description,
                    "short_name": config.short_name,
                }
                for name, config in cls.PILLARS.items()
            },
            "layout": cls.LAYOUT,
            "visualization": cls.VISUALIZATION,
            "color_schemes": cls.COLOR_SCHEMES,
            "animations": cls.ANIMATIONS,
            "chill_mode": cls.CHILL_MODE,
        }
    
    @classmethod
    def get_zen_theme(cls) -> Dict[str, Any]:
        """Get Zen theme specifically."""
        return {
            "name": "zen",
            "colors": cls.COLOR_SCHEMES["zen"],
            "pillars": cls.PILLARS,
            "layout": "radial",
            "animations": {
                "default": "smooth",
                "presets": cls.ANIMATIONS,
            },
            "features": {
                "meditation": True,
                "chill_mode": True,
                "guided_wellbeing": True,
                "ai_recommendations": True,
            },
        }
    
    @classmethod
    def get_pillar_details(cls, pillar: str) -> Dict[str, Any]:
        """Get detailed configuration for a pillar."""
        if pillar not in cls.PILLARS:
            return {}
        
        config = cls.PILLARS[pillar]
        
        # Pillar-specific endpoints
        endpoints = {
            "happiness": [
                {"method": "POST", "path": "/wellbeing/happiness/unlock", "action": "Track achievement"},
                {"method": "GET", "path": "/wellbeing/happiness/score", "action": "Get score"},
            ],
            "health": [
                {"method": "POST", "path": "/wellbeing/health/check", "action": "Run health check"},
                {"method": "GET", "path": "/wellbeing/health/status", "action": "Get status"},
            ],
            "love": [
                {"method": "POST", "path": "/wellbeing/community/connect", "action": "Connect users"},
                {"method": "POST", "path": "/wellbeing/community/share", "action": "Share task"},
            ],
            "freedom": [
                {"method": "POST", "path": "/wellbeing/freedom/register-provider", "action": "Register provider"},
                {"method": "GET", "path": "/wellbeing/freedom/score", "action": "Get score"},
            ],
            "leisure": [
                {"method": "POST", "path": "/wellbeing/leisure/automate", "action": "Create automation"},
                {"method": "POST", "path": "/wellbeing/leisure/execute", "action": "Execute automations"},
            ],
            "wealth": [
                {"method": "POST", "path": "/wellbeing/wealth/optimize", "action": "Optimize resources"},
                {"method": "GET", "path": "/wellbeing/wealth/score", "action": "Get score"},
            ],
            "peace": [
                {"method": "POST", "path": "/wellbeing/peace/meditate", "action": "Start meditation"},
                {"method": "POST", "path": "/wellbeing/peace/chill", "action": "Enable chill mode"},
                {"method": "POST", "path": "/wellbeing/peace/quiet-hours", "action": "Set quiet hours"},
            ],
        }
        
        return {
            "name": config.name,
            "icon": config.icon,
            "color": config.color,
            "description": config.description,
            "short_name": config.short_name,
            "endpoints": endpoints.get(pillar, []),
        }
    
    @classmethod
    def get_ai_dashboard_config(cls) -> Dict[str, Any]:
        """Get AI optimization dashboard configuration."""
        return {
            "title": "🤖 AI Wellbeing Assistant",
            "features": [
                {
                    "title": "Pattern Analysis",
                    "icon": "📊",
                    "endpoint": "/api/wellbeing/ai/analyze-patterns",
                    "description": "Analyze patterns in your wellbeing data"
                },
                {
                    "title": "24h Prediction",
                    "icon": "🔮",
                    "endpoint": "/api/wellbeing/ai/predict-wellbeing",
                    "description": "Predict your wellbeing for next 24 hours"
                },
                {
                    "title": "Smart Recommendations",
                    "icon": "💡",
                    "endpoint": "/api/wellbeing/ai/recommendations",
                    "description": "Get personalized AI recommendations"
                },
                {
                    "title": "Chill Mode Optimizer",
                    "icon": "✨",
                    "endpoint": "/api/wellbeing/ai/optimize-chill",
                    "description": "AI-optimized chill mode settings"
                },
                {
                    "title": "Predict Next Action",
                    "icon": "🎯",
                    "endpoint": "/api/wellbeing/ai/predict-next-action",
                    "description": "Predict what you'll do next"
                },
            ],
            "feedback": {
                "endpoint": "/api/wellbeing/ai/feedback",
                "description": "Help AI learn from your feedback"
            }
        }


# HTML/CSS for dashboard
DASHBOARD_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AVA Wellbeing Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto;
            background: #0F1419;
            color: #E8E8E8;
            overflow-x: hidden;
        }
        
        .dashboard {
            min-height: 100vh;
            padding: 2rem;
            background: linear-gradient(135deg, #0F1419 0%, #1a1f2e 100%);
        }
        
        .header {
            text-align: center;
            margin-bottom: 3rem;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #62F0E4, #4A90E2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .mandala-container {
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 3rem 0;
            perspective: 1000px;
        }
        
        .mandala {
            position: relative;
            width: 400px;
            height: 400px;
            border-radius: 50%;
            background: radial-gradient(circle at 30% 30%, rgba(98, 240, 228, 0.1), transparent);
            display: flex;
            justify-content: center;
            align-items: center;
        }
        
        .center-core {
            position: absolute;
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: radial-gradient(circle, #62F0E4, #4A90E2);
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 2rem;
            box-shadow: 0 0 30px rgba(98, 240, 228, 0.5);
            animation: pulse 2s ease-in-out infinite;
        }
        
        .pillar-arc {
            position: absolute;
            width: 100%;
            height: 100%;
        }
        
        .pillar {
            position: absolute;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 2rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .pillar:hover {
            transform: scale(1.2);
            box-shadow: 0 0 20px currentColor;
        }
        
        .pillar-progress {
            position: absolute;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            border: 3px solid;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        
        .recommendations {
            max-width: 1200px;
            margin: 3rem auto;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
        }
        
        .recommendation-card {
            background: rgba(98, 240, 228, 0.05);
            border: 1px solid rgba(98, 240, 228, 0.2);
            border-radius: 12px;
            padding: 1.5rem;
            transition: all 0.3s ease;
        }
        
        .recommendation-card:hover {
            background: rgba(98, 240, 228, 0.1);
            border-color: rgba(98, 240, 228, 0.5);
            transform: translateY(-4px);
        }
        
        .recommendation-card h3 {
            margin-bottom: 0.5rem;
            color: #62F0E4;
        }
        
        .chill-mode {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(15, 20, 25, 0.95);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            opacity: 0;
        }
        
        .chill-mode.active {
            display: flex;
            opacity: 1;
        }
        
        @keyframes pulse {
            0%, 100% {
                box-shadow: 0 0 30px rgba(98, 240, 228, 0.5);
            }
            50% {
                box-shadow: 0 0 60px rgba(98, 240, 228, 0.8);
            }
        }
        
        @keyframes float {
            0%, 100% {
                transform: translateY(0px);
            }
            50% {
                transform: translateY(-10px);
            }
        }
        
        .floating {
            animation: float 3s ease-in-out infinite;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>AVA Wellbeing Dashboard 🌟</h1>
            <p>7 Pillars of Human Flourishing</p>
        </div>
        
        <div class="mandala-container">
            <div class="mandala floating">
                <div class="center-core">
                    <span id="overall-score">0</span>
                </div>
                <!-- Pillars will be positioned via JavaScript -->
            </div>
        </div>
        
        <div class="recommendations" id="recommendations">
            <!-- AI recommendations will load here -->
        </div>
        
        <div class="chill-mode" id="chillMode">
            <div style="text-align: center;">
                <h2 style="font-size: 3rem; margin-bottom: 1rem;">🧘</h2>
                <h3 style="font-size: 1.5rem; margin-bottom: 0.5rem; color: #62F0E4;">Breathe...</h3>
                <p style="color: #999; font-size: 1.1rem;">Time for peace and rest</p>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="dashboard.js"></script>
</body>
</html>
"""

# JavaScript for dashboard interaction
DASHBOARD_JS_TEMPLATE = """
// AVA Wellbeing Dashboard JavaScript

const API_BASE = '/api/wellbeing';

// Pillar positions on mandala (7 pillars arranged in circle)
const PILLAR_ANGLES = {
    'happiness': 0,
    'health': 51.4,
    'love': 102.8,
    'freedom': 154.2,
    'leisure': 205.6,
    'wealth': 257,
    'peace': 308.4
};

class WellbeingDashboard {
    constructor() {
        this.scores = {};
        this.recommendations = {};
        this.init();
    }
    
    async init() {
        await this.loadWellbeingScores();
        await this.loadRecommendations();
        this.renderMandala();
        this.renderRecommendations();
    }
    
    async loadWellbeingScores() {
        try {
            const response = await fetch(`${API_BASE}/overall`);
            const data = await response.json();
            this.scores = data.pillar_scores;
            document.getElementById('overall-score').textContent = Math.round(data.overall_score);
        } catch (error) {
            console.error('Failed to load wellbeing scores:', error);
        }
    }
    
    async loadRecommendations() {
        try {
            const response = await fetch(`${API_BASE}/ai/recommendations`);
            const data = await response.json();
            this.recommendations = data.recommendations;
        } catch (error) {
            console.error('Failed to load recommendations:', error);
        }
    }
    
    renderMandala() {
        const mandala = document.querySelector('.mandala');
        
        for (const [pillar, angle] of Object.entries(PILLAR_ANGLES)) {
            const score = this.scores[pillar] || 0;
            const pillarEl = document.createElement('div');
            pillarEl.className = 'pillar';
            
            // Position pillar on circle
            const radius = 150;
            const radians = (angle * Math.PI) / 180;
            const x = Math.cos(radians) * radius;
            const y = Math.sin(radians) * radius;
            
            pillarEl.style.left = `calc(50% + ${x}px)`;
            pillarEl.style.top = `calc(50% + ${y}px)`;
            pillarEl.style.transform = 'translate(-50%, -50%)';
            pillarEl.innerHTML = `<div style="font-size: 2rem;">${this.getPillarIcon(pillar)}</div>`;
            
            pillarEl.onclick = () => this.showPillarDetails(pillar);
            mandala.appendChild(pillarEl);
        }
    }
    
    getPillarIcon(pillar) {
        const icons = {
            'happiness': '💚',
            'health': '🏥',
            'love': '💕',
            'freedom': '🦅',
            'leisure': '🌴',
            'wealth': '💰',
            'peace': '🧘'
        };
        return icons[pillar] || '✨';
    }
    
    renderRecommendations() {
        const container = document.getElementById('recommendations');
        container.innerHTML = '';
        
        for (const [pillar, recs] of Object.entries(this.recommendations)) {
            if (Array.isArray(recs)) {
                recs.forEach(rec => {
                    const card = document.createElement('div');
                    card.className = 'recommendation-card';
                    card.innerHTML = `
                        <h3>${this.getPillarIcon(pillar)} ${pillar.toUpperCase()}</h3>
                        <p>${rec}</p>
                    `;
                    container.appendChild(card);
                });
            }
        }
    }
    
    showPillarDetails(pillar) {
        console.log(`Showing details for ${pillar} with score: ${this.scores[pillar]}`);
    }
    
    enableChillMode(hours = 2, intensity = 0.5) {
        const chillMode = document.getElementById('chillMode');
        chillMode.classList.add('active');
        setTimeout(() => chillMode.classList.remove('active'), hours * 60 * 60 * 1000);
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    const dashboard = new WellbeingDashboard();
});
"""
