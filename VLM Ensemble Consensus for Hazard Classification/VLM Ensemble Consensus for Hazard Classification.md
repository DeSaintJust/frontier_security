# VLM Ensemble Consensus for Hazard Classification

## Description
This mitigation implements a robust ensemble voting mechanism using multiple, diverse Vision-Language Models (VLMs) for maritime hazard classification in autonomous surface vessels. The approach requires strict majority consensus among independently sampled model inferences before accepting hazard classifications, significantly reducing single-model failures and stochastic errors. The system operates within the alert-to-override interval specified by the IMO MASS Code, ensuring semantic awareness of out-of-distribution anomalies while maintaining human-overridable authority.

The ensemble approach follows a "fast-slow" pipeline where a lightweight anomaly detector triggers detailed VLM reasoning only when needed. Multiple VLM calls with distinct random seeds generate independent classifications, which are aggregated using strict majority voting with tie-breaking defaults to conservative station-keeping behavior. This design addresses the inherent uncertainty in rare, semantic maritime hazards that require contextual understanding beyond geometric analysis.

## Effect
When a threat event occurs (semantic anomaly detection triggering fallback maneuver selection), this mitigation provides:

1. **Reduced False Positives/Negatives**: Ensemble consensus filters out spurious individual model errors, decreasing both false hazard detections and missed hazards by approximately 40-60% compared to single-model baselines (as demonstrated in Experiments 1-2).

2. **Improved Alignment with Human Judgment**: FB-3 ensemble achieves 68% alignment with aggregated human "Acceptable" judgments versus 45-50% for single-model or geometry-only baselines, ensuring fallback maneuvers match operator expectations.

3. **Stochastic Error Mitigation**: Multiple independent inferences with different random seeds (η₁, η₂, η₃) reduce variance in hazard recognition, particularly for low-salience cues like diver-down flags where individual model performance varies significantly.

4. **Graceful Degradation**: When consensus cannot be reached (ties or insufficient agreement), the system defaults to station-keeping (ID 0) and notifies the remote operator, preventing unsafe autonomous actions under uncertainty.

5. **Latency-Aware Safety**: The ensemble can be configured with faster, lighter models for time-critical responses while maintaining reliability through consensus, with sub-10-second models retaining 83% of the awareness of slower state-of-the-art models.

## Implementation

### Core Ensemble Configuration
```yaml
# ensemble_config.yaml
ensemble:
  name: "Maritime Hazard Classifier Ensemble"
  voting_scheme: "strict_majority"
  fallback_action: "station_keeping"
  models:
    - provider: "openai"
      model: "gpt-5-low"
      weight: 1.0
      latency_budget_ms: 17000
      temperature: 0.7
      seed_variants: [42, 137, 289]
      
    - provider: "google"
      model: "gemini-2.5-flash"
      weight: 1.0
      latency_budget_ms: 15500
      temperature: 0.7
      seed_variants: [43, 138, 290]
      
    - provider: "anthropic"
      model: "claude-sonnet-4"
      weight: 1.0
      latency_budget_ms: 4500
      temperature: 0.7
      seed_variants: [44, 139, 291]
  
  consensus:
    minimum_votes: 3
    majority_threshold: "floor(n/2) + 1"
    tie_resolution: "fallback_to_station_keeping"
    confidence_aggregation: "mean"
    
  timing:
    max_total_latency_ms: 30000
    parallel_execution: true
    timeout_handling: "partial_consensus"
    
  output_schema:
    format: "json_strict"
    required_fields:
      - "hazard_type"
      - "confidence"
      - "implications"
      - "recommended_action"
      - "choice_id"
    validation: "schema_first"
