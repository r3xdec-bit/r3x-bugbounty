"""
R3X AI Mixer Provider & Task Definitions
"""
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class TaskRole(str, Enum):
    CLASSIFICATION = "classification"       # Fast model for triage & categorization
    DEEP_REASONING = "deep_reasoning"       # Powerful model for complex vulnerability analysis
    CODE_ANALYSIS = "code_analysis"         # Specialized for JavaScript & API schema audit
    REPORTING = "reporting"                 # Comprehensive narrative and remediation writing
    LOCAL_FAST = "local_fast"               # Offline local Ollama model for simple tasks

class ProviderConfig(BaseModel):
    name: str
    base_url: str
    default_model: str
    supported_models: List[str]
    input_cost_per_m: float = 0.0   # USD per 1M tokens
    output_cost_per_m: float = 0.0  # USD per 1M tokens
    max_rpm: int = 60               # Requests per minute rate limit
    requires_key: bool = True

DEFAULT_PROVIDERS: Dict[str, ProviderConfig] = {
    "nvidia": ProviderConfig(
        name="nvidia",
        base_url="https://integrate.api.nvidia.com/v1",
        default_model="meta/llama-3.3-70b-instruct",
        supported_models=[
            "meta/llama-3.3-70b-instruct",
            "meta/llama-3.1-8b-instruct",
            "mistralai/mixtral-8x22b-instruct",
            "deepseek-ai/deepseek-r1"
        ],
        input_cost_per_m=0.70,
        output_cost_per_m=0.90,
        max_rpm=60
    ),
    "openai": ProviderConfig(
        name="openai",
        base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        supported_models=["gpt-4o-mini", "gpt-4o", "o3-mini"],
        input_cost_per_m=0.15,
        output_cost_per_m=0.60,
        max_rpm=500
    ),
    "openrouter": ProviderConfig(
        name="openrouter",
        base_url="https://openrouter.ai/api/v1",
        default_model="anthropic/claude-3.5-sonnet",
        supported_models=[
            "anthropic/claude-3.5-sonnet",
            "meta-llama/llama-3.3-70b-instruct",
            "google/gemini-2.0-flash-exp:free"
        ],
        input_cost_per_m=3.0,
        output_cost_per_m=15.0,
        max_rpm=120
    ),
    "gemini": ProviderConfig(
        name="gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        default_model="gemini-1.5-flash",
        supported_models=["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash"],
        input_cost_per_m=0.075,
        output_cost_per_m=0.30,
        max_rpm=1500
    ),
    "ollama": ProviderConfig(
        name="ollama",
        base_url="http://localhost:11434/v1",
        default_model="llama3.2:latest",
        supported_models=["llama3.2:latest", "mistral:latest", "qwen2.5-coder:latest"],
        input_cost_per_m=0.0,
        output_cost_per_m=0.0,
        max_rpm=1000,
        requires_key=False
    ),
    "custom": ProviderConfig(
        name="custom",
        base_url="http://localhost:8000/v1",
        default_model="default-model",
        supported_models=["default-model"],
        input_cost_per_m=0.0,
        output_cost_per_m=0.0,
        max_rpm=1000,
        requires_key=False
    )
}
