import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_error, mean_squared_error

# Set paths
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # Moves up one directory
file_path = os.path.join(base_dir, "data", "extended_crop_sales_data.csv")  # Correct dataset path
model_dir = os.path.join(base_dir, "models")  # Directory to store models
os.makedirs(model_dir, exist_ok=True)  # Create 'models' folder if it doesn't exist

# Load dataset
df = pd.read_csv(file_path)

# Convert 'Date' column to datetime format
df["Date"] = pd.to_datetime(df["Date"])
df["Month"] = df["Date"].dt.month
df["Year"] = df["Date"].dt.year

# Get unique crops
unique_crops = df["Crop Name"].unique()
print(f"Training models for {len(unique_crops)} crops...")

# Dictionary to store future predictions
future_predictions = {}

# Train a model for each crop
for crop in unique_crops:
    print(f"Training model for {crop}...")

    # Filter dataset for current crop
    df_crop = df[df["Crop Name"] == crop].copy()

    # Define features (X) and target (y)
    X = df_crop[["Month", "Year", "Price (₹)"]]
    y = df_crop["Sales (kg)"]

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train model
    model = LinearRegression()
    model.fit(X_train, y_train)

    # Evaluate model
    y_pred = model.predict(X_test)
    mae = mean_absolute_error(y_test, y_pred)
    rmse = np.sqrt(mean_squared_error(y_test, y_pred))
    print(f"{crop} - MAE: {mae:.2f}, RMSE: {rmse:.2f}")

    # Save trained model
    model_path = os.path.join(model_dir, f"{crop.replace(' ', '_')}_model.pkl")
    joblib.dump(model, model_path)

    # Generate future predictions for the next 5 months
    future_data = pd.DataFrame({
        "Month": [1, 2, 3, 4, 5],  # Future months
        "Year": [2025] * 5,  # Future year
        "Price (₹)": np.linspace(df_crop["Price (₹)"].min(), df_crop["Price (₹)"].max(), 5)  # Simulating prices
    })
    
    future_demand = model.predict(future_data)
    future_data["Predicted Sales (kg)"] = future_demand

    # Store predictions
    future_predictions[crop] = future_data

# Save all predictions to CSV
future_predictions_df = pd.concat(future_predictions, names=["Crop Name"])
future_predictions_df.to_csv(os.path.join(base_dir, "data", "future_demand_predictions.csv"))

print("✅ Training complete! Models saved in 'models/' directory.")
print("✅ Future predictions saved in 'data/future_demand_predictions.csv'.")
