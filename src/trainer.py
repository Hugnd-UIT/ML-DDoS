import pandas as pd
import joblib
from xgboost import XGBClassifier
import os
import time

def main():
    print("[*] Starting training process")
    start_time = time.time()

    train_path = './data/train_binary.csv'
    test_path = './data/test_binary.csv'
    
    print("[*] Loading data...")
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)
    
    df_full = pd.concat([df_train, df_test], ignore_index=True)
    
    X = df_full.drop(columns=['Label'])
    y = df_full['Label']
    print(f"[+] Loaded {X.shape[0]} flows.")

    print("[*] Training...")
    model = XGBClassifier(
        n_estimators=150, 
        max_depth=7, 
        tree_method='hist',
        eval_metric='logloss', 
        random_state=42, 
        n_jobs=-1
    )
    
    model.fit(X, y)
    
    os.makedirs('./models', exist_ok=True)
    joblib.dump(model, './models/binary.pkl')
    
    print(f"[+] Training completed. binary.pkl is ready.")
    print(f"[+] Time: {time.time() - start_time:.2f}s.")

if __name__ == "__main__":
    main()