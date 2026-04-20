"""
Machine Learning Model Training for Phishing Detection
Trains Random Forest classifier
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score
)
import joblib
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

def load_data(filepath):
    """Load feature dataset"""
    print("=" * 60)
    print("LOADING DATASET")
    print("=" * 60)
    
    print(f"\n📂 Loading features from: {filepath}")
    df = pd.read_csv(filepath)
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    print(f"✅ Dataset loaded")
    print(f"\n📊 Dataset Information:")
    print(f"   Total samples: {len(df)}")
    print(f"   Number of features: {X.shape[1]}")
    print(f"\n   Class distribution:")
    print(f"   Legitimate (0): {sum(y==0):,} ({sum(y==0)/len(y)*100:.1f}%)")
    print(f"   Phishing (1):   {sum(y==1):,} ({sum(y==1)/len(y)*100:.1f}%)")
    
    return X, y, X.columns.tolist()

def train_model(X_train, y_train):
    """Train Random Forest classifier"""
    print("\n" + "=" * 60)
    print("TRAINING RANDOM FOREST MODEL")
    print("=" * 60)
    
    print("\n🤖 Model Configuration:")
    print("   Algorithm: Random Forest")
    print("   Number of trees: 100")
    print("   Max depth: 20")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=10,
        min_samples_leaf=4,
        random_state=42,
        n_jobs=-1
    )
    
    print("\n⏳ Training model...")
    model.fit(X_train, y_train)
    print("✅ Model training complete!")
    
    # Cross-validation
    print("\n🔄 Performing 5-fold cross-validation...")
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy', n_jobs=-1)
    
    print(f"   CV Scores: {[f'{score:.4f}' for score in cv_scores]}")
    print(f"   Mean CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    return model

def evaluate_model(model, X_test, y_test, X_train, y_train):
    """Evaluate model performance"""
    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)
    
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    train_accuracy = model.score(X_train, y_train)
    
    print("\n🎯 PERFORMANCE METRICS:")
    print("=" * 60)
    print(f"   Accuracy:   {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"   Precision:  {precision:.4f}")
    print(f"   Recall:     {recall:.4f}")
    print(f"   F1-Score:   {f1:.4f}")
    
    print(f"\n   Training Accuracy: {train_accuracy:.4f}")
    print(f"   Test Accuracy:     {accuracy:.4f}")
    
    if train_accuracy - accuracy > 0.05:
        print(f"   ⚠️  Warning: Possible overfitting")
    else:
        print(f"   ✅ Good generalization")
    
    print("\n📋 DETAILED CLASSIFICATION REPORT:")
    print("=" * 60)
    print(classification_report(y_test, y_pred, 
                                target_names=['Legitimate', 'Phishing'],
                                digits=4))
    
    cm = confusion_matrix(y_test, y_pred)
    print("\n🔢 CONFUSION MATRIX:")
    print("=" * 60)
    print(f"\n                 Predicted")
    print(f"                 Legit  Phish")
    print(f"   Actual Legit  {cm[0][0]:5d}  {cm[0][1]:5d}")
    print(f"          Phish  {cm[1][0]:5d}  {cm[1][1]:5d}")
    
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    print(f"\n   True Negatives:  {tn} (correctly identified legitimate)")
    print(f"   False Positives: {fp} (legitimate marked as phishing) - {fpr*100:.2f}%")
    print(f"   False Negatives: {fn} (phishing marked as legitimate) - {fnr*100:.2f}%")
    print(f"   True Positives:  {tp} (correctly identified phishing)")
    
    plot_confusion_matrix(cm)
    
    return accuracy, precision, recall, f1

def plot_confusion_matrix(cm):
    """Plot confusion matrix"""
    try:
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Legitimate', 'Phishing'],
                    yticklabels=['Legitimate', 'Phishing'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig('data/models/confusion_matrix.png', dpi=300)
        plt.close()
        print("\n💾 Confusion matrix saved: data/models/confusion_matrix.png")
    except:
        print("\n⚠️  Could not save confusion matrix plot")

def analyze_feature_importance(model, feature_names):
    """Analyze feature importance"""
    print("\n" + "=" * 60)
    print("FEATURE IMPORTANCE ANALYSIS")
    print("=" * 60)
    
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    print("\n⭐ TOP 15 MOST IMPORTANT FEATURES:")
    print("=" * 60)
    for i in range(min(15, len(feature_names))):
        idx = indices[i]
        print(f"   {i+1:2d}. {feature_names[idx]:30s} {importances[idx]:.4f}")
    
    try:
        plt.figure(figsize=(12, 8))
        top_n = min(20, len(importances))
        top_indices = indices[:top_n]
        
        plt.barh(range(top_n), importances[top_indices])
        plt.yticks(range(top_n), [feature_names[i] for i in top_indices])
        plt.xlabel('Importance')
        plt.title('Top Feature Importance')
        plt.tight_layout()
        plt.savefig('data/models/feature_importance.png', dpi=300)
        plt.close()
        print("\n💾 Feature importance plot saved!")
    except:
        print("\n⚠️  Could not save feature importance plot")

def save_model(model, filepath='data/models/phishing_detector.pkl'):
    """Save trained model"""
    print("\n" + "=" * 60)
    print("SAVING MODEL")
    print("=" * 60)
    
    print(f"\n💾 Saving model to: {filepath}")
    joblib.dump(model, filepath)
    print(f"✅ Model saved successfully")

def main():
    start_time = datetime.now()
    
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 14 + "PHISHBANE - MODEL TRAINING" + " " * 18 + "║")
    print("╚" + "=" * 58 + "╝")
    print(f"\nStarted: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Load data
    X, y, feature_names = load_data('data/processed/features.csv')
    
    # Split data
    print("\n✂️  Splitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   Training set: {len(X_train)} samples")
    print(f"   Test set: {len(X_test)} samples")
    
    # Train model
    model = train_model(X_train, y_train)
    
    # Evaluate
    accuracy, precision, recall, f1 = evaluate_model(model, X_test, y_test, X_train, y_train)
    
    # Feature importance
    analyze_feature_importance(model, feature_names)
    
    # Save model
    save_model(model)
    
    # Final summary
    end_time = datetime.now()
    elapsed = (end_time - start_time).total_seconds()
    
    print("\n" + "=" * 60)
    print("✅ MODEL TRAINING COMPLETE!")
    print("=" * 60)
    
    print(f"\n🎯 FINAL RESULTS:")
    print(f"   Model Accuracy: {accuracy*100:.2f}%")
    print(f"   Precision:      {precision*100:.2f}%")
    print(f"   Recall:         {recall*100:.2f}%")
    print(f"   F1-Score:       {f1*100:.2f}%")
    
    print(f"\n📁 Files Created:")
    print(f"   data/models/phishing_detector.pkl")
    print(f"   data/models/confusion_matrix.png")
    print(f"   data/models/feature_importance.png")
    
    print(f"\n⏱️  Total Time: {elapsed:.2f} seconds")
    
    print(f"\n🎯 Next Steps:")
    print(f"   1. Check data/models/ for visualizations")
    print(f"   2. Git commit your work")
    print(f"   3. Tomorrow: Build web interface")

if __name__ == "__main__":
    main()
