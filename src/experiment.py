import os
import time

import pandas as pd

from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import f1_score
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier


# Run model benchmark
def main():
    # Get the current script directory
    current_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    # Build dataset paths
    train_path = os.path.join(
        current_dir,
        "../data/train_binary.csv"
    )

    test_path = os.path.join(
        current_dir,
        "../data/test_binary.csv"
    )

    # Check whether the required datasets exist
    if (
        not os.path.exists(train_path)
        or not os.path.exists(test_path)
    ):
        print(
            "[-] Error: Dataset not found."
        )

        print(
            f"    Train: {train_path}"
        )

        print(
            f"    Test: {test_path}"
        )

        return

    # Load training and testing data
    train_df = pd.read_csv(
        train_path
    )

    test_df = pd.read_csv(
        test_path
    )

    # Separate training features and labels
    X_train = train_df.drop(
        columns=["Label"]
    )

    y_train = train_df["Label"]

    # Separate testing features and labels
    X_test = test_df.drop(
        columns=["Label"]
    )

    y_test = test_df["Label"]

    # Create Decision Tree model
    dt_model = DecisionTreeClassifier(
        random_state=42
    )

    # Create Random Forest model
    rf_model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )

    # Create XGBoost model
    xgb_model = XGBClassifier(
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )

    # Create hard voting ensemble
    voting_model = VotingClassifier(
        estimators=[
            ("dt", dt_model),
            ("rf", rf_model),
            ("xgb", xgb_model)
        ],
        voting="hard",
        n_jobs=-1
    )

    # Store all models for benchmarking
    models = {
        "Decision Tree": dt_model,
        "Random Forest": rf_model,
        "XGBoost": xgb_model,
        "Voting Classifier": voting_model
    }

    # Store benchmark results
    results = []

    # Train and evaluate every model
    for model_name, model in models.items():
        # Train the current model
        model.fit(
            X_train,
            y_train
        )

        # Start inference timer
        start_time = time.time()

        # Run predictions on the test dataset
        y_pred = model.predict(
            X_test
        )

        # Stop inference timer
        end_time = time.time()

        # Calculate F1 score
        f1 = f1_score(
            y_test,
            y_pred
        )

        # Calculate total inference time
        total_inference_time = (
            end_time - start_time
        )

        # Count the number of test samples
        num_samples = len(
            X_test
        )

        # Calculate average latency per sample
        latency_per_sample_ms = (
            total_inference_time
            / num_samples
            * 1000
        )

        # Store benchmark results
        results.append(
            {
                "Model Name": model_name,
                "F1-Score": f1,
                "Latency (ms)": latency_per_sample_ms
            }
        )

    # Print benchmark header
    print(
        "=" * 60
    )

    print(
        f"{'MODEL BENCHMARK RESULTS':^60}"
    )

    print(
        "=" * 60
    )

    # Print benchmark table header
    print(
        f"{'Model Name':<25} | "
        f"{'F1-Score':<15} | "
        f"{'Latency (ms)':<15}"
    )

    print(
        "-" * 60
    )

    # Print benchmark results
    for row in results:
        print(
            f"{row['Model Name']:<25} | "
            f"{row['F1-Score']:<15.4f} | "
            f"{row['Latency (ms)']:<15.6f}"
        )

    # Print benchmark footer
    print(
        "=" * 60
    )


# Start the benchmark program
if __name__ == "__main__":
    main()