import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import os
import pickle

def train_post_harvest_model():
    # Construct the CSV file path
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'post_harvest_data.csv')

    # Load the dataset
    data = pd.read_csv(csv_path)

    # Features: temperature, humidity, crop_type
    X = data[['temperature', 'humidity', 'crop_type']]
    X = pd.get_dummies(X, columns=['crop_type'])  # Encode crop names as numeric

    # Target: spoilage_days (convert to binary labels for classification)
    y = data['spoilage_days'].apply(lambda x: 1 if x < 5 else 0)  # Spoiled if < 5 days

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train the Random Forest model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model accuracy: {accuracy * 100:.2f}%")

    # Save the model using pickle
    model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ml_models')
    os.makedirs(model_dir, exist_ok=True)  # Create directory if it doesn't exist
    model_path = os.path.join(model_dir, 'post_harvest_model.pkl')
    
    with open(model_path, 'wb') as file:
        pickle.dump(model, file)
    
    print(f"Model saved successfully at: {model_path}")

    # Also save feature columns for reference
    feature_columns = X.columns.tolist()
    with open(os.path.join(model_dir, 'feature_columns.pkl'), 'wb') as f:
        pickle.dump(feature_columns, f)
    
    print("Feature columns saved successfully")
    return model

# Run training
if __name__ == "__main__":
    model = train_post_harvest_model()
