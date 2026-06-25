"""
============================================================
 train_model.py — Offline ML Training Script
 Cyber Risk & Threat Intelligence System
============================================================
 Loads a Kaggle network security CSV (e.g., NSL-KDD),
 dynamically identifies features and labels, trains a KNN
 classifier, evaluates it, and exports the model as model.pkl.
============================================================
"""

import os
import sys
import glob
import warnings

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

# Suppress convergence and future warnings for cleaner output
warnings.filterwarnings("ignore")

# ============================================================
# Configuration Constants
# ============================================================
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
MODEL_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")
TEST_SIZE = 0.25          # 75/25 train-test split
RANDOM_STATE = 42         # Reproducibility seed
KNN_NEIGHBORS = 5         # K value for KNN classifier
MODEL_TYPE = "knn"        # "knn" or "naive_bayes"


def discover_dataset(data_dir: str) -> list:
    """
    Automatically discovers all CSV files in the data directory.

    Args:
        data_dir: Path to the directory containing CSV files.

    Returns:
        List of full paths to the discovered CSV files.

    Raises:
        FileNotFoundError: If no CSV files are found in the directory.
    """
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"[ERROR] No CSV files found in '{data_dir}'. "
            f"Please download or generate network security datasets "
            f"and place the CSV files in the 'data/' directory."
        )

    print(f"[INFO] Discovered datasets: {[os.path.basename(f) for f in csv_files]}")
    return csv_files


def load_and_preprocess(csv_paths: list) -> tuple:
    """
    Loads one or more CSV files, concatenates them, and performs preprocessing:
      - Drops rows with missing values.
      - Dynamically identifies feature columns (X) and the target label (y).
      - Encodes categorical features using LabelEncoder.
      - Scales numerical features using StandardScaler.

    Args:
        csv_paths: List of paths to the CSV files.

    Returns:
        Tuple of (X_train, X_test, y_train, y_test, scaler, encoders,
                  feature_names, label_encoder).
    """
    dfs = []
    for csv_path in csv_paths:
        print(f"[INFO] Loading dataset from: {csv_path}")
        df_part = pd.read_csv(csv_path)
        print(f"[INFO] Loaded part shape: {df_part.shape[0]} rows x {df_part.shape[1]} columns")
        dfs.append(df_part)

    df = pd.concat(dfs, ignore_index=True)
    print(f"[INFO] Combined dataset shape: {df.shape[0]} rows x {df.shape[1]} columns")

    # --- Drop rows with missing values ---
    original_rows = len(df)
    df.dropna(inplace=True)
    dropped = original_rows - len(df)
    if dropped > 0:
        print(f"[INFO] Dropped {dropped} rows with missing values.")

    # --- Dynamic column indexing ---
    # The LAST column is treated as the target label (y).
    # ALL other columns are features (X).
    feature_cols = df.columns[:-1].tolist()
    target_col = df.columns[-1]

    print(f"[INFO] Target column (y): '{target_col}'")
    print(f"[INFO] Feature columns (X): {len(feature_cols)} columns")

    # --- Encode the target label ---
    label_encoder = LabelEncoder()
    df[target_col] = label_encoder.fit_transform(df[target_col].astype(str))
    print(f"[INFO] Target classes: {list(label_encoder.classes_)}")

    # --- Encode categorical feature columns ---
    encoders = {}  # Store encoders for each categorical column
    for col in feature_cols:
        if df[col].dtype == "object":
            enc = LabelEncoder()
            df[col] = enc.fit_transform(df[col].astype(str))
            encoders[col] = enc
            print(f"[INFO] Encoded categorical column: '{col}' "
                  f"({len(enc.classes_)} unique values)")

    # --- Split features and target ---
    X = df[feature_cols].values
    y = df[target_col].values

    # --- Scale features ---
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # --- Train-test split ---
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    print(f"[INFO] Training set: {X_train.shape[0]} samples")
    print(f"[INFO] Testing set:  {X_test.shape[0]} samples")

    return (X_train, X_test, y_train, y_test,
            scaler, encoders, feature_cols, label_encoder)



def train_model(X_train: np.ndarray, y_train: np.ndarray,
                model_type: str = "knn") -> object:
    """
    Trains the selected ML classifier.

    Args:
        X_train:    Training features (scaled).
        y_train:    Training labels (encoded).
        model_type: Either "knn" or "naive_bayes".

    Returns:
        Trained sklearn classifier instance.
    """
    if model_type == "knn":
        print(f"\n[TRAIN] Training KNN classifier (k={KNN_NEIGHBORS})...")
        model = KNeighborsClassifier(n_neighbors=KNN_NEIGHBORS)
    elif model_type == "naive_bayes":
        print("\n[TRAIN] Training Gaussian Naive Bayes classifier...")
        model = GaussianNB()
    else:
        raise ValueError(f"[ERROR] Unknown model type: '{model_type}'. "
                         f"Choose 'knn' or 'naive_bayes'.")

    model.fit(X_train, y_train)
    print("[TRAIN] Model training complete.")
    return model


def evaluate_model(model, X_test: np.ndarray, y_test: np.ndarray,
                   label_encoder: LabelEncoder) -> float:
    """
    Evaluates the trained model and prints metrics.

    Args:
        model:          Trained sklearn classifier.
        X_test:         Test features.
        y_test:         True test labels.
        label_encoder:  LabelEncoder used on the target column.

    Returns:
        Accuracy score as a float.
    """
    print("\n" + "=" * 60)
    print(" MODEL EVALUATION RESULTS")
    print("=" * 60)

    y_pred = model.predict(X_test)

    # --- Accuracy ---
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n  Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)")

    # --- Classification Report ---
    print(f"\n  Classification Report:")
    print("-" * 60)
    target_names = [str(c) for c in label_encoder.classes_]
    report = classification_report(y_test, y_pred, target_names=target_names,
                                   zero_division=0)
    print(report)

    # --- Confusion Matrix ---
    print(f"  Confusion Matrix:")
    print("-" * 60)
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print("=" * 60)

    return accuracy


def export_model(model, scaler, encoders, feature_cols,
                 label_encoder, output_path: str) -> None:
    """
    Exports the trained model pipeline as a single .pkl file.

    The exported dictionary contains:
      - 'model':          The trained classifier
      - 'scaler':         The fitted StandardScaler
      - 'encoders':       Dict of LabelEncoders for categorical features
      - 'feature_cols':   List of feature column names
      - 'label_encoder':  LabelEncoder for target column

    Args:
        model:          Trained classifier.
        scaler:         Fitted StandardScaler.
        encoders:       Dict of fitted LabelEncoders for features.
        feature_cols:   List of feature column names.
        label_encoder:  Fitted LabelEncoder for the target.
        output_path:    File path for the exported .pkl file.
    """
    pipeline = {
        "model": model,
        "scaler": scaler,
        "encoders": encoders,
        "feature_cols": feature_cols,
        "label_encoder": label_encoder,
    }

    joblib.dump(pipeline, output_path)
    file_size = os.path.getsize(output_path) / 1024  # KB
    print(f"\n[EXPORT] Model pipeline saved to: {output_path}")
    print(f"[EXPORT] File size: {file_size:.1f} KB")


def main():
    """
    Main execution flow:
      1. Discover the dataset CSV in /data.
      2. Load, preprocess, and split the data.
      3. Train the ML model (KNN or Naive Bayes).
      4. Evaluate and print metrics.
      5. Export the trained pipeline as model.pkl.
    """
    print("\n" + "=" * 60)
    print(" CYBER RISK & THREAT INTELLIGENCE SYSTEM")
    print(" Offline ML Training Module")
    print("=" * 60 + "\n")

    try:
        # Step 1: Discover datasets
        csv_paths = discover_dataset(DATA_DIR)

        # Step 2: Load and preprocess
        (X_train, X_test, y_train, y_test,
         scaler, encoders, feature_cols, label_encoder) = load_and_preprocess(csv_paths)

        # Step 3: Train the model
        model = train_model(X_train, y_train, model_type=MODEL_TYPE)

        # Step 4: Evaluate the model
        accuracy = evaluate_model(model, X_test, y_test, label_encoder)

        # Step 5: Export the trained pipeline
        export_model(model, scaler, encoders, feature_cols,
                     label_encoder, MODEL_OUTPUT)

        print(f"\n[SUCCESS] Training pipeline complete. "
              f"Model accuracy: {accuracy * 100:.2f}%")

    except FileNotFoundError as e:
        print(f"\n{e}")
        sys.exit(1)

    except pd.errors.EmptyDataError:
        print("\n[ERROR] The CSV file is empty. Please provide a valid dataset.")
        sys.exit(1)

    except ValueError as e:
        print(f"\n[ERROR] Data processing error: {e}")
        sys.exit(1)

    except Exception as e:
        print(f"\n[ERROR] Unexpected error during training: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
