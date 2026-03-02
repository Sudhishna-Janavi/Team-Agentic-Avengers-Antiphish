# This module handles model training and evaluation.
import logging
import joblib
import os
import pandas as pd
import numpy as np
import warnings

from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    average_precision_score, roc_auc_score, confusion_matrix, 
    classification_report, f1_score, accuracy_score
)
from sklearn.model_selection import cross_val_score

# Silence non-critical warnings for cleaner logs
warnings.filterwarnings('ignore', category=UserWarning, module='xgboost')
warnings.filterwarnings('ignore', category=UserWarning, module='lightgbm')

def train_and_evaluate(X_train, X_test, y_train, y_test):
    """
    Executes training for 4 classification models and generates a 
    comprehensive performance audit in the /results directory.
    """
    
    # 1. Model Definitions
    models = {
        "RandomForest": RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42),
        "XGBoost": XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42),
        "LightGBM": LGBMClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42, verbose=-1),
        "LogisticRegression": Pipeline([
            ('scaler', StandardScaler()), 
            ('lr', LogisticRegression(max_iter=1000, random_state=42))
        ])
    }
    
    results_list = []
    
    # 2. Workspace Initialization
    for folder in ['models', 'results']:
        if not os.path.exists(folder):
            os.makedirs(folder)

    report_path = os.path.join('results', 'model_performance_report.txt')

    # 3. Training and Diagnostic Loop
    with open(report_path, 'w') as f:
        f.write("PHISHING DETECTION PIPELINE - MODEL PERFORMANCE AUDIT\n")
        f.write("="*55 + "\n\n")

        for name, model in models.items():
            logging.info(f"Training {name}...")
            model.fit(X_train, y_train)
            
            # --- Primary Metrics ---
            y_pred = model.predict(X_test)
            y_probs = model.predict_proba(X_test)[:, 1]
            
            acc = accuracy_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            report = classification_report(y_test, y_pred)

            # --- Error Analysis (Confusion Matrix) ---
            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = cm.ravel()
            
            # --- Curve Summaries (AUC & PR Score) ---
            auc_roc = roc_auc_score(y_test, y_probs)
            avg_precision = average_precision_score(y_test, y_probs)

            # --- Stability Analysis (Cross-Validation) ---
            cv_scores = cross_val_score(model, X_train, y_train, cv=3, scoring='f1')
            cv_mean = np.mean(cv_scores)

            # --- Feature Importance Extraction ---
            try:
                if hasattr(model, 'feature_importances_'):
                    importances = pd.Series(model.feature_importances_, index=X_test.columns)
                elif name == "LogisticRegression":
                    coefs = model.named_steps['lr'].coef_[0]
                    importances = pd.Series(abs(coefs), index=X_test.columns)
                
                top_features = importances.sort_values(ascending=False).head(5).to_string()
            except Exception as e:
                top_features = f"Unavailable: {e}"

            # 4. Documenting Findings
            logging.info(f"{name} Completed | Acc: {acc:.4f} | F1: {f1:.4f} | FP: {fp}")
            
            f.write(f"MODEL: {name}\n")
            f.write("-" * len(f"MODEL: {name}") + "\n")
            f.write(f"1. Overall Accuracy: {acc:.4f}\n")
            f.write(f"2. F1-Score:         {f1:.4f}\n")
            f.write(f"3. 3-Fold CV F1:     {cv_mean:.4f}\n")
            f.write(f"4. AUC-ROC Score:    {auc_roc:.4f} (Separation Power)\n")
            f.write(f"5. Avg Precision:    {avg_precision:.4f} (PR Curve Summary)\n\n")
            
            f.write("CONFUSION MATRIX:\n")
            f.write(f"  [True Neg: {tn}]  [False Pos: {fp}] <-- (Legit Blocked)\n")
            f.write(f"  [False Neg: {fn}] [True Pos: {tp}] <-- (Phishing Caught)\n\n")
            
            f.write(f"TOP SIGNIFICANT FEATURES:\n{top_features}\n\n")
            f.write(f"DETAILED CLASSIFICATION REPORT:\n{report}\n")
            f.write("="*55 + "\n\n")

            results_list.append({"Model": name, "Accuracy": acc, "F1-Score": f1})
            
            # 5. Export Model Artifact
            joblib.dump(model, f"models/{name.lower()}.joblib")

    logging.info(f"Pipeline Audit saved to: {report_path}")
    return results_list