import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# Load dataset
data_path = os.path.join("data", "sample_data.csv")
df = pd.read_csv(data_path)

# Convert labels to numbers
df['label'] = df['label'].map({'normal': 0, 'attack': 1})

# Features and target
X = df.drop('label', axis=1)
y = df['label']

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Save model
model_path = os.path.join("model", "ids_model.pkl")
joblib.dump(model, model_path)

print("✅ Model trained and saved successfully!")
