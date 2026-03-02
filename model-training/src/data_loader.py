# Loads and cleans the data
import sqlite3
import pandas as pd
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_and_clean_data(relative_path='data/phishing.db'):
    logging.info(f"Starting data ingestion from {relative_path}...")

    # construct absolute path to database
    base_path = os.getcwd()
    absolute_db_path = os.path.join(base_path, relative_path)
    
    if not os.path.exists(absolute_db_path):
        logging.error(f"Database not found at {absolute_db_path}")
        raise FileNotFoundError(f"Database missing at {absolute_db_path}")
    
    # ingest with sqlite
    conn = sqlite3.connect(absolute_db_path)
    df = pd.read_sql_query("SELECT * FROM phishing_data", conn)
    conn.close()
    logging.info(f"Successfully loaded {len(df)} rows.")

    # drop artifacts to prevent leakage 
    if 'Unnamed: 0' in df.columns:
        df = df.drop(columns=['Unnamed: 0'])

    # rectify contaminated numerical data 
    logging.info("Imputing missing values and clipping contaminated data...")
    df['NoOfImage'] = df['NoOfImage'].clip(lower=0)
    df['LineOfCode'] = df['LineOfCode'].fillna(df['LineOfCode'].median())

    # string sanitization to merge the eCommerce duplicates found during EDA
    df['Industry'] = df['Industry'].str.strip().str.title().fillna('Unknown')
    df['HostingProvider'] = df['HostingProvider'].str.strip().str.title().fillna('Unknown Provider')

    # shuffle to prevent learning database order 
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    logging.info("Data cleaning and shuffling complete.")
    
    return df