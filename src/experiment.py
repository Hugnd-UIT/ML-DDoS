import os
import time
import pandas as pd
from sklearn.metrics import f1_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    train_path = os.path.join(current_dir, '../data/training/train_binary.csv')
    test_path = os.path.join(current_dir, '../data/testing/test_binary.csv')
    
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print("Error: Dataset not found. Please check paths:")
        print(f"Train: {train_path}")
        print(f"Test: {test_path}")
        return

    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    X_train = train_df.drop(columns=['Label'])
    y_train = train_df['Label']
    
    X_test = test_df.drop(columns=['Label'])
    y_test = test_df['Label']

    dt_model = DecisionTreeClassifier(random_state=42)
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    xgb_model = XGBClassifier(eval_metric='logloss', random_state=42, n_jobs=-1)
    
    voting_model = VotingClassifier(
        estimators=[
            ('dt', dt_model), 
            ('rf', rf_model), 
            ('xgb', xgb_model)
        ], 
        voting='hard',
        n_jobs=-1
    )

    models = {
        'Decision Tree': dt_model,
        'Random Forest': rf_model,
        'XGBoost': xgb_model,
        'Voting Classifier': voting_model
    }

    results = []

    for model_name, model in models.items():
        model.fit(X_train, y_train)
        
        start_time = time.time()
        y_pred = model.predict(X_test)
        end_time = time.time()
        
        f1 = f1_score(y_test, y_pred)
        
        total_inference_time = end_time - start_time
        num_samples = len(X_test)
        latency_per_sample_ms = (total_inference_time / num_samples) * 1000
        
        results.append({
            'Model Name': model_name,
            'F1-Score': f1,
            'Latency (ms)': latency_per_sample_ms
        })

    print("=" * 60)
    print(f"{'MODEL BENCHMARK RESULTS':^60}")
    print("=" * 60)
    print(f"{'Model Name':<25} | {'F1-Score':<15} | {'Latency (ms)':<15}")
    print("-" * 60)
    for row in results:
        print(f"{row['Model Name']:<25} | {row['F1-Score']:<15.4f} | {row['Latency (ms)']:<15.6f}")
    print("=" * 60)

if __name__ == "__main__":
    main()
