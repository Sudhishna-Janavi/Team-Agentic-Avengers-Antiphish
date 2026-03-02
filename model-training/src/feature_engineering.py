# Feature engineering and encoding based on EDA insights to enhance model performance
import pandas as pd
import numpy as np
import re
from sklearn.preprocessing import LabelEncoder
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def clean_feature_names(df):
    """Sanitizes column names for compatibility with XGBoost/LightGBM."""
    # Replaces special JSON characters and spaces with underscores to prevent crashes
    df.columns = [re.sub(r'[\[\]{}":, ]', '_', col) for col in df.columns]
    return df

def engineer_features(df):
    """
    Main feature engineering pipeline based on EDA insights.
    """
    logging.info("Starting feature engineering...")

    # 1. Clean Column Names
    df = clean_feature_names(df)

    # 2. Obfuscation Index (Custom Feature)
    # Rationale: Phishing sites often use long obfuscated lines in short files.
    df['ObfuscationIndex'] = df['LargestLineLength'] / (df['LineOfCode'] + 1)

    # 3. Domain Age Binning (Based on EDA Bimodal Spikes)
    # Captures the risk 'danger zones' found at 0-12 and 35-60 months
    bins = [0, 12, 34, 60, df['DomainAgeMonths'].max() + 1]
    labels = [0, 1, 2, 3] # 'New', 'Stable', 'Aged_Risk', 'Old'
    df['AgeCategory'] = pd.cut(df['DomainAgeMonths'], bins=bins, labels=labels, include_lowest=True).astype(int)

    # 4. Feature Combination (Redundancy Reduction)
    # Combines moderate correlations identified in Multivariate Heatmap
    df['TotalRedirects'] = df['NoOfURLRedirect'] + df['NoOfSelfRedirect']

    # 5. Categorical Encoding
    # High-cardinality features like Industry and HostingProvider are converted to numeric
    le = LabelEncoder()
    categorical_cols = ['Industry', 'HostingProvider']
    for col in categorical_cols:
        # astype(str) ensures consistency if 'Unknown' was injected during loading
        df[f'{col}_Enc'] = le.fit_transform(df[col].astype(str))

    # 6. Final Feature Selection
    # Keep only predictive numerical/encoded features, dropping raw text and leakage artifacts
    features_to_keep = [
        'LineOfCode', 'NoOfiFrame', 'NoOfImage', 'NoOfExternalRef', 
        'Robots', 'IsResponsive', 'DomainAgeMonths', 'ObfuscationIndex', 
        'AgeCategory', 'TotalRedirects', 'Industry_Enc', 'HostingProvider_Enc', 
        'label' # Keep label for splitting, drop later in training script
    ]
    
    # Ensure all requested columns exist before filtering
    final_cols = [c for c in features_to_keep if c in df.columns]
    
    logging.info(f"Feature engineering complete. Total features: {len(final_cols) - 1}")
    
    # Generate a preview of the engineered dataset for the logs
    logging.info("--- Engineered Feature Preview ---")
    logging.info(f"\n{df[final_cols].head().to_string()}")
    
    # Log the distribution for the new AgeCategory
    logging.info(f"Age Category Distribution:\n{df['AgeCategory'].value_counts().sort_index()}")
    return df[final_cols]