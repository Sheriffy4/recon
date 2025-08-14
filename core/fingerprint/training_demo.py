#!/usr/bin/env python3
# recon/core/fingerprint/training_demo.py
"""
Demo script for DPI ML classifier training pipeline.
Demonstrates training data preparation, model training, and evaluation.
"""

import os
import sys
import logging
from pathlib import Path

# Add the recon directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.fingerprint.model_trainer import ModelTrainer
from core.fingerprint.training_data import TrainingDataGenerator, FeatureEngineer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

LOG = logging.getLogger("training_demo")


def demo_training_data_generation():
    """Demonstrate training data generation and validation."""
    print("\n" + "="*60)
    print("TRAINING DATA GENERATION DEMO")
    print("="*60)
    
    generator = TrainingDataGenerator()
    
    # Show base examples
    print(f"\nBase training examples: {len(generator.training_examples)}")
    
    # Show class distribution
    distribution = generator.get_class_distribution()
    print("\nClass distribution:")
    for dpi_type, count in distribution.items():
        print(f"  {dpi_type}: {count}")
    
    # Generate synthetic variations
    print("\nGenerating synthetic variations...")
    synthetic = generator.generate_synthetic_variations(base_examples=3)
    print(f"Generated {len(synthetic)} synthetic examples")
    
    # Get complete training data
    training_data = generator.get_training_data(include_synthetic=True)
    print(f"\nTotal training examples: {len(training_data)}")
    
    # Validate training data
    validation = generator.validate_training_data()
    print(f"\nValidation results:")
    print(f"  Total examples: {validation['total_examples']}")
    print(f"  Missing features: {validation['missing_features']}")
    print(f"  Feature coverage: {len(validation['feature_coverage'])} features")
    
    # Show sample example
    sample = training_data[0]
    print(f"\nSample training example:")
    print(f"  DPI Type: {sample['dpi_type']}")
    print(f"  Confidence: {sample['confidence']:.3f}")
    print(f"  Metrics count: {len(sample['metrics'])}")
    print(f"  Sample metrics: {list(sample['metrics'].keys())[:10]}...")
    
    return training_data


def demo_feature_engineering(training_data):
    """Demonstrate feature engineering pipeline."""
    print("\n" + "="*60)
    print("FEATURE ENGINEERING DEMO")
    print("="*60)
    
    engineer = FeatureEngineer()
    
    # Fit the pipeline
    print("\nFitting feature engineering pipeline...")
    engineer.fit(training_data)
    print(f"Feature statistics calculated for {len(engineer.feature_stats)} features")
    
    # Transform sample metrics
    sample_metrics = training_data[0]['metrics']
    print(f"\nTransforming sample metrics...")
    print(f"Original metrics: {len(sample_metrics)} features")
    
    features = engineer.transform(sample_metrics)
    print(f"Engineered features: {len(features)} features")
    
    # Show feature types
    normalized_features = [k for k in features.keys() if '_normalized' in k]
    minmax_features = [k for k in features.keys() if '_minmax' in k]
    boolean_features = [k for k in features.keys() if k in sample_metrics and isinstance(sample_metrics[k], bool)]
    
    print(f"\nFeature types:")
    print(f"  Normalized features: {len(normalized_features)}")
    print(f"  MinMax features: {len(minmax_features)}")
    print(f"  Boolean features: {len(boolean_features)}")
    
    # Show sample engineered features
    print(f"\nSample engineered features:")
    for i, (key, value) in enumerate(list(features.items())[:10]):
        print(f"  {key}: {value:.4f}")
    
    return engineer


def demo_model_training(training_data):
    """Demonstrate model training and evaluation."""
    print("\n" + "="*60)
    print("MODEL TRAINING DEMO")
    print("="*60)
    
    try:
        import sklearn
        print(f"sklearn version: {sklearn.__version__}")
    except ImportError:
        print("sklearn not available - training demo will be limited")
        return None
    
    # Create trainer
    trainer = ModelTrainer("demo_dpi_classifier.joblib")
    
    # Train model
    print(f"\nTraining model with {len(training_data)} examples...")
    print("This may take a few moments...")
    
    try:
        metrics = trainer.train_model_with_evaluation(
            training_data=training_data,
            test_size=0.2,
            cv_folds=3
        )
        
        print(f"\nTraining completed!")
        print(f"Model accuracy: {metrics.accuracy:.3f}")
        print(f"Cross-validation score: {metrics.cross_val_mean:.3f} ± {metrics.cross_val_std:.3f}")
        
        # Show feature importance
        feature_report = trainer.get_feature_importance_report(top_n=5)
        print(f"\nTop 5 most important features:")
        for i, (feature, importance) in enumerate(feature_report['top_features'], 1):
            print(f"  {i}. {feature}: {importance:.4f}")
        
        # Test predictions
        print(f"\nTesting predictions on sample data...")
        for i in range(min(3, len(training_data))):
            sample = training_data[i]
            predicted_type, confidence = trainer.ml_classifier.classify_dpi(sample['metrics'])
            actual_type = sample['dpi_type']
            
            status = "✓" if predicted_type == actual_type else "✗"
            print(f"  {status} Predicted: {predicted_type} ({confidence:.3f}) | Actual: {actual_type}")
        
        return trainer
        
    except Exception as e:
        print(f"Training failed: {e}")
        return None


def demo_evaluation_and_reporting(trainer):
    """Demonstrate evaluation and reporting capabilities."""
    if trainer is None or trainer.evaluation_metrics is None:
        print("\nNo trained model available for evaluation demo")
        return
    
    print("\n" + "="*60)
    print("EVALUATION AND REPORTING DEMO")
    print("="*60)
    
    # Generate comprehensive report
    report = trainer.generate_training_report()
    print(report)
    
    # Save results
    print(f"\nSaving results...")
    trainer.save_evaluation_results("demo_evaluation_results.json")
    
    with open("demo_training_report.txt", 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"Results saved to:")
    print(f"  - demo_evaluation_results.json")
    print(f"  - demo_training_report.txt")
    print(f"  - demo_dpi_classifier.joblib")


def demo_model_usage():
    """Demonstrate using the trained model for classification."""
    print("\n" + "="*60)
    print("MODEL USAGE DEMO")
    print("="*60)
    
    try:
        from core.fingerprint.ml_classifier import MLClassifier
        
        # Load trained model
        classifier = MLClassifier("demo_dpi_classifier.joblib")
        
        if not classifier.is_trained:
            print("No trained model found. Run training demo first.")
            return
        
        print("Loaded trained model successfully!")
        
        # Test with sample metrics
        sample_metrics = {
            'rst_ttl': 63,
            'rst_latency_ms': 15.2,
            'rst_from_target': False,
            'connection_latency_ms': 45.8,
            'dns_resolution_time_ms': 12.3,
            'handshake_time_ms': 89.4,
            'stateful_inspection': True,
            'quic_udp_blocked': True,
            'ech_blocked': True,
            'tls_version_sensitivity': 'blocks_tls13',
            'ipv6_handling': 'throttled'
        }
        
        print(f"\nClassifying sample DPI behavior...")
        dpi_type, confidence = classifier.classify_dpi(sample_metrics)
        
        print(f"Predicted DPI type: {dpi_type}")
        print(f"Confidence: {confidence:.3f}")
        
        # Show model info
        model_info = classifier.get_model_info()
        print(f"\nModel information:")
        for key, value in model_info.items():
            print(f"  {key}: {value}")
        
    except Exception as e:
        print(f"Model usage demo failed: {e}")


def main():
    """Run complete training pipeline demo."""
    print("DPI ML CLASSIFIER TRAINING PIPELINE DEMO")
    print("This demo showcases the complete training pipeline for the DPI classifier")
    
    try:
        # Demo 1: Training data generation
        training_data = demo_training_data_generation()
        
        # Demo 2: Feature engineering
        engineer = demo_feature_engineering(training_data)
        
        # Demo 3: Model training
        trainer = demo_model_training(training_data)
        
        # Demo 4: Evaluation and reporting
        demo_evaluation_and_reporting(trainer)
        
        # Demo 5: Model usage
        demo_model_usage()
        
        print("\n" + "="*60)
        print("DEMO COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("\nFiles created:")
        print("  - demo_dpi_classifier.joblib (trained model)")
        print("  - demo_evaluation_results.json (evaluation metrics)")
        print("  - demo_training_report.txt (comprehensive report)")
        print("\nYou can now use the trained model in your DPI fingerprinting system!")
        
    except Exception as e:
        LOG.error(f"Demo failed: {e}")
        print(f"\nDemo failed with error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())