from flask import Flask, request, render_template
import joblib
from feature_extraction import classify_url
import pandas as pd
import os

app = Flask(__name__)

# Load your pre-trained model
try:
    model = joblib.load('model.joblib')
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return render_template('index.html', prediction_text='Error: Model not loaded.')
        
    url_to_check = request.form['url']
    
    try:
        features_dict = classify_url(url_to_check)
        features_df = pd.DataFrame([features_dict])
    except Exception as e:
        return render_template('index.html', prediction_text=f'Error in feature extraction: {e}')

    # Make prediction
    try:
        prediction = model.predict(features_df)[0]
        proba = model.predict_proba(features_df)[0]
        confidence = round(proba[prediction] * 100, 2)
        
        # Note: Your code says prediction == 0 is phishing, == 1 is legitimate
        result = 'Phishing URL' if prediction == 0 else 'Legitimate URL'
        
        return render_template('index.html', 
                             prediction_text=f'{result} ({confidence}% confidence)', 
                             url=url_to_check)
    except Exception as e:
        return render_template('index.html', 
                             prediction_text=f'Error in prediction: {e}', 
                             url=url_to_check)

if __name__ == '__main__':
    app.run(debug=True)