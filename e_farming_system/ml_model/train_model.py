import pandas as pd
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
import pickle
import os

# Ensure ml_model directory exists
os.makedirs('ml_model', exist_ok=True)

# Add these debug prints at the start
print("Current working directory:", os.getcwd())
print("Script directory:", os.path.dirname(os.path.abspath(__file__)))

# Step 1: Load the dataset
script_dir = os.path.dirname(os.path.abspath(__file__))
csv_file_path = os.path.join(script_dir, "market_prices.csv")

try:
    # Check if the file exists before reading
    if os.path.exists(csv_file_path):
        print(f"File found at: {csv_file_path}")
        data = pd.read_csv(csv_file_path)
    else:
        raise FileNotFoundError(f"Error: {csv_file_path} not found!")

    # Step 2: Preprocessing
    data['Date'] = pd.to_datetime(data['Date'])
    data['Date'] = data['Date'].map(pd.Timestamp.toordinal)

    # Step 3: Train a model for each crop
    crop_models = {}

    # Print available crops for debugging
    print("Available crops in dataset:", data.columns[1:].tolist())

    # Iterate over each crop column (excluding the 'Date' column)
    for crop in data.columns[1:]:
        print(f"\nTraining model for: {crop}")  # Debug print
        
        crop_data = data[['Date', crop]].dropna()  # Remove any NaN values
        
        # Check if the crop data has enough points to train a model
        if len(crop_data) < 2:
            print(f"Skipping {crop}: Not enough data points")
            continue
        
        X = crop_data[['Date']]
        y = crop_data[crop]
        
        try:
            # Train-test split
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Create and train the model
            model = LinearRegression()
            model.fit(X_train, y_train)
            
            # Update the model saving path to use absolute path
            model_filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                        f"price_model_{crop.lower().replace(' ', '_')}.pkl")
            
            # Save model for each crop
            with open(model_filename, 'wb') as f:
                pickle.dump(model, f)
            
            # Add these prints after saving
            print(f"Saved model file exists: {os.path.exists(model_filename)}")
            print(f"Model file size: {os.path.getsize(model_filename) if os.path.exists(model_filename) else 'File not found'}")
            
            print(f"✅ Model saved for {crop} at: {model_filename}")
            crop_models[crop] = model_filename
            
        except Exception as e:
            print(f"Error training model for {crop}: {str(e)}")

    print("\nFinal crop models dictionary:", crop_models)

except Exception as e:
    print(f"Error in training process: {str(e)}")
