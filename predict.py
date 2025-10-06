import joblib
import numpy as np
from feature_extraction import classify_url
import pandas as pd

# Load model
model = joblib.load("model.joblib")

def predict_url(url):
    features = classify_url(url)
    X = pd.DataFrame([features])
    prediction = model.predict(X)[0]
    proba = model.predict_proba(X)[0]

    if prediction == 0:
        print(f"[PHISHING] {url},[{proba[0]*100}]")

    else:
        print(f"[LEGITIMATE] {url},[{proba[1]*100}]")

# Test
if __name__ == "__main__":
    test_url = "https://github.com/openai"
    predict_url(test_url)