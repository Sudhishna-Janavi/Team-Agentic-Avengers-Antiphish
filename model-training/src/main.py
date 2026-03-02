# This is the entry point for the end-to-end phishing detection pipeline.
import logging
import os
from sklearn.model_selection import train_test_split

# Import the custom modules
from data_loader import load_and_clean_data
from feature_engineering import engineer_features
from model_trainer import train_and_evaluate

# Configure logging for the run.sh output
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def run_pipeline():
    logging.info("--- Starting End-to-End Phishing Detection Pipeline ---")

    # 1. Ingest: Fetch data using SQLite with a relative path
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, 'data', 'phishing.db')
    df = load_and_clean_data(db_path)

    # 2. Process: Execute feature engineering logic based on EDA findings 
    df_engineered = engineer_features(df)

    # 3. Split: Prepare training and testing sets for evaluation
    X = df_engineered.drop(columns=['label'])
    y = df_engineered['label']
    
    # Using stratify=y to maintain class balance in the split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logging.info(f"Data split successful. Training samples: {X_train.shape[0]}")

    # 4. Train & Evaluate: Train models and generate performance reports
    results = train_and_evaluate(X_train, X_test, y_train, y_test)

    logging.info("--- Pipeline Execution Complete ---")
    
    # Print final summary for the logs
    print("\nFINAL MODEL PERFORMANCE SUMMARY:")
    print(f"{'Model':<20} | {'Accuracy':<10} | {'F1-Score':<10}")
    print("-" * 45)
    for res in results:
        print(f"{res['Model']:<20} | {res['Accuracy']:<10.4f} | {res['F1-Score']:<10.4f}")

if __name__ == "__main__":
    try:
        run_pipeline()
    except Exception as e:
        logging.error(f"Pipeline failed: {e}")
        exit(1) # Ensures run.sh reflects a failure if it occurs