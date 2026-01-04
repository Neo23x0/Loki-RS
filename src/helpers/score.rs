/// Score calculation utilities
/// Implements weighted score calculation formula

/// Calculate weighted score from sub-scores
/// 
/// Formula: score = 100 * (1 - ∏(1 - sᵢ/100/2ⁱ))
/// Where sub-scores are sorted in descending order
/// 
/// # Arguments
/// * `sub_scores` - Vector of sub-scores (reasons)
/// 
/// # Returns
/// Total weighted score (0.0 to 100.0)
pub fn calculate_weighted_score(sub_scores: &[i16]) -> f64 {
    if sub_scores.is_empty() {
        return 0.0;
    }
    
    // Filter positive scores and sort descending
    let mut sorted: Vec<i16> = sub_scores.iter()
        .filter(|&&s| s > 0)
        .copied()
        .collect();
    
    if sorted.is_empty() {
        return 0.0;
    }
    
    sorted.sort_by(|a, b| b.cmp(a));  // Descending order
    
    // Calculate product: ∏(1 - sᵢ/100/2ⁱ)
    let mut product = 1.0;
    for (i, &score) in sorted.iter().enumerate() {
        let term = 1.0 - (score as f64 / 100.0 / 2_f64.powi(i as i32));
        product *= term;
    }
    
    // Final score: 100 * (1 - product)
    100.0 * (1.0 - product)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_score() {
        let scores = vec![75];
        let result = calculate_weighted_score(&scores);
        assert!((result - 75.0).abs() < 0.001);
    }

    #[test]
    fn test_multiple_identical() {
        let scores = vec![70, 70, 70];
        let result = calculate_weighted_score(&scores);
        // Calculated: 83.9125
        assert!((result - 83.9125).abs() < 0.1);
    }

    #[test]
    fn test_descending_scores() {
        let scores = vec![80, 60, 40];
        let result = calculate_weighted_score(&scores);
        // Calculated: 87.4
        assert!((result - 87.4).abs() < 0.1);
    }

    #[test]
    fn test_ascending_scores() {
        // Should sort to descending first
        let scores = vec![40, 60, 80];
        let result = calculate_weighted_score(&scores);
        // Should be same as descending (87.4)
        assert!((result - 87.4).abs() < 0.1);
    }

    #[test]
    fn test_with_zeros() {
        let scores = vec![70, 0, 50];
        let result = calculate_weighted_score(&scores);
        // Should ignore 0, calculated: 77.5
        assert!((result - 77.5).abs() < 0.1);
    }

    #[test]
    fn test_maximum_score() {
        let scores = vec![100, 100, 100];
        let result = calculate_weighted_score(&scores);
        assert!((result - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_empty_scores() {
        let scores: Vec<i16> = vec![];
        let result = calculate_weighted_score(&scores);
        assert!((result - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_example_from_docs() {
        // Example: [70, 70, 50, 40, 40] should give ~84.20
        let scores = vec![70, 70, 50, 40, 40];
        let result = calculate_weighted_score(&scores);
        assert!((result - 84.195859375).abs() < 0.01);
    }
}

