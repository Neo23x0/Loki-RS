# Score Calculation Implementation Guide

This document describes the weighted score calculation formula used in Loki2.

## Formula

Given sub-scores (s₀, s₁, s₂, ..., sₙ) ordered in **descending order**, the total score is calculated as:

```
score = 100 * (1 - ∏(1 - sᵢ/100/2ⁱ))
```

Where:
- `sᵢ` is the i-th sub-score (ordered descending)
- `2ⁱ` is 2 raised to the power of i (2⁰, 2¹, 2², ...)
- `∏` is the product of all terms

## Rust Implementation

```rust
fn calculate_weighted_score(sub_scores: &[i16]) -> f64 {
    if sub_scores.is_empty() {
        return 0.0;
    }
    
    // Sort descending (highest first)
    let mut sorted: Vec<i16> = sub_scores.iter()
        .filter(|&&s| s > 0)  // Only positive scores
        .copied()
        .collect();
    sorted.sort_by(|a, b| b.cmp(a));  // Descending
    
    // Calculate product
    let mut product = 1.0;
    for (i, &score) in sorted.iter().enumerate() {
        let term = 1.0 - (score as f64 / 100.0 / 2_f64.powi(i as i32));
        product *= term;
    }
    
    // Final score
    100.0 * (1.0 - product)
}
```

## Example Calculation

```rust
let sub_scores = vec![70, 70, 50, 40, 40];
let total_score = calculate_weighted_score(&sub_scores);
// Result: ~84.20
```

Step-by-step:
1. Sort: [70, 70, 50, 40, 40] (already descending)
2. Calculate terms:
   - i=0: 1 - 70/100/2⁰ = 1 - 0.7 = 0.3
   - i=1: 1 - 70/100/2¹ = 1 - 0.35 = 0.65
   - i=2: 1 - 50/100/2² = 1 - 0.125 = 0.875
   - i=3: 1 - 40/100/2³ = 1 - 0.05 = 0.95
   - i=4: 1 - 40/100/2⁴ = 1 - 0.025 = 0.975
3. Product: 0.3 × 0.65 × 0.875 × 0.95 × 0.975 ≈ 0.158
4. Score: 100 × (1 - 0.158) ≈ 84.20

## Properties

1. **Capped at 100**: Maximum possible score is 100
2. **Weighted**: Higher scores contribute more
3. **Diminishing returns**: Lower scores contribute less
4. **Order matters**: Must sort descending before calculation
5. **Only positive**: Negative or zero scores are excluded

## Integration Points

### Where to Calculate

1. **File matches**: After all IOC/YARA matches for a file
2. **Process matches**: After all YARA matches for a process
3. **Display**: Show both sub-scores (reasons) and total score

### Display Format

```
FILE: /path/to/file SCORE: 84.20
REASON_1: Hash match HASH: abc123... SUBSCORE: 70
REASON_2: YARA match RULE: SuspiciousRule SUBSCORE: 70
REASON_3: Filename match PATTERN: .*malware.* SUBSCORE: 50
```

### Thresholds

- **Alert**: total_score ≥ 80
- **Warning**: total_score ≥ 60
- **Notice**: total_score ≥ 40

## Testing

Test cases to implement:

1. **Single sub-score**: `[75]` → should be 75.0
2. **Multiple identical**: `[70, 70, 70]` → should be ~87.5
3. **Descending**: `[80, 60, 40]` → should be ~88.75
4. **Ascending** (should sort): `[40, 60, 80]` → should be ~88.75
5. **With zeros**: `[70, 0, 50]` → should ignore 0, result ~82.5
6. **Maximum**: `[100, 100, 100]` → should be 100.0
7. **Empty**: `[]` → should be 0.0

## Edge Cases

1. **Very high sub-scores**: Multiple 90+ scores → approaches 100 quickly
2. **Many low scores**: Many 10-20 scores → total stays relatively low
3. **Mixed**: High + many low → high score dominates
4. **Floating point precision**: Use appropriate precision for display


