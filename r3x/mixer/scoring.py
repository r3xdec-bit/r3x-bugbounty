"""
R3X Dynamic Model Scoring & Intelligent Selection Engine
Calculates fitness scores for AI models based on speed, token cost, task fit, and provider stability.
"""
from r3x.mixer.key_store import key_store
from r3x.mixer.models import DEFAULT_PROVIDERS, TaskRole


class ModelScoringEngine:
    def __init__(self):
        # Weights for fitness evaluation
        self.weights = {
            "task_affinity": 0.40,
            "cost_efficiency": 0.25,
            "latency_speed": 0.20,
            "provider_stability": 0.15
        }

    def compute_fitness(
        self,
        provider_name: str,
        model_name: str,
        role: TaskRole,
        recent_latency_ms: float = 300.0,
        recent_failures: int = 0
    ) -> float:
        """
        Compute normalized fitness score between 0.0 and 1.0.
        Higher score = optimal candidate for this specific task.
        """
        cfg = DEFAULT_PROVIDERS.get(provider_name.lower())
        if not cfg:
            return 0.0

        # 1. Task Affinity Score
        affinity = 0.5
        if role == TaskRole.CLASSIFICATION:
            # Fast, lightweight models favored
            if "8b" in model_name.lower() or "mini" in model_name.lower() or "flash" in model_name.lower():
                affinity = 1.0
            else:
                affinity = 0.6
        elif role == TaskRole.DEEP_REASONING:
            # Heavy reasoning models favored over mini/flash variants
            if "mini" in model_name.lower() or "flash" in model_name.lower() or "8b" in model_name.lower():
                affinity = 0.6
            elif "70b" in model_name.lower() or "gpt-4o" in model_name.lower() or "sonnet" in model_name.lower() or "r1" in model_name.lower():
                affinity = 1.0
            else:
                affinity = 0.5
        elif role == TaskRole.CODE_ANALYSIS:
            if "coder" in model_name.lower() or "sonnet" in model_name.lower() or "gpt-4o" in model_name.lower():
                affinity = 1.0
            else:
                affinity = 0.7
        elif role == TaskRole.LOCAL_FAST:
            affinity = 1.0 if provider_name.lower() in ["ollama", "custom"] else 0.2

        # 2. Cost Efficiency Score (inverse of cost)
        total_cost_per_m = cfg.input_cost_per_m + cfg.output_cost_per_m
        if total_cost_per_m <= 0.0:
            cost_score = 1.0  # Free/local
        elif total_cost_per_m < 1.0:
            cost_score = 0.85
        elif total_cost_per_m < 5.0:
            cost_score = 0.60
        else:
            cost_score = 0.30

        # 3. Latency Score
        if recent_latency_ms <= 200:
            latency_score = 1.0
        elif recent_latency_ms <= 600:
            latency_score = 0.8
        elif recent_latency_ms <= 1500:
            latency_score = 0.5
        else:
            latency_score = 0.2

        # 4. Stability Score (penalize recent failures)
        stability_score = max(0.0, 1.0 - (recent_failures * 0.25))

        # Composite Weighted Score
        total_score = (
            affinity * self.weights["task_affinity"] +
            cost_score * self.weights["cost_efficiency"] +
            latency_score * self.weights["latency_speed"] +
            stability_score * self.weights["provider_stability"]
        )

        return round(total_score, 3)

    def rank_candidates(self, role: TaskRole) -> list[tuple[str, str, float]]:
        """
        Rank all configured providers and models for a given task role.
        Returns: [(provider_name, model_name, fitness_score), ...] sorted descending.
        """
        candidates = []
        for prov_name, cfg in DEFAULT_PROVIDERS.items():
            active_keys = key_store.get_keys(prov_name, active_only=True)
            if cfg.requires_key and not active_keys:
                continue

            # Pick default model or role-specific model
            failures = sum(k.failed_count for k in active_keys) if active_keys else 0
            score = self.compute_fitness(
                provider_name=prov_name,
                model_name=cfg.default_model,
                role=role,
                recent_failures=failures
            )
            candidates.append((prov_name, cfg.default_model, score))

        candidates.sort(key=lambda x: x[2], reverse=True)
        return candidates

model_scoring = ModelScoringEngine()
