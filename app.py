from flask import Flask, request, render_template, jsonify
import joblib
from feature_extraction import classify_url
import pandas as pd

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
        response = {'url': '', 'result': 'Error: Model not loaded', 'confidence': 0}
        return jsonify(response) if request.is_json else render_template('index.html', prediction_text=response['result'])

    # Get URL from JSON or form data
    url_to_check = ''
    if request.is_json:
        data = request.get_json()
        url_to_check = data.get('url', '').strip()
    else:
        url_to_check = request.form.get('url', '').strip()

    if not url_to_check:
        response = {'url': '', 'result': 'Error: No URL provided', 'confidence': 0}
        return jsonify(response) if request.is_json else render_template('index.html', prediction_text=response['result'])

    # Feature extraction
    try:
        features_dict = classify_url(url_to_check)
        features_df = pd.DataFrame([features_dict])
    except Exception as e:
        response = {'url': url_to_check, 'result': f'Error in feature extraction: {e}', 'confidence': 0}
        return jsonify(response) if request.is_json else render_template('index.html', prediction_text=response['result'], url=url_to_check)

    # Make prediction
    try:
        prediction = model.predict(features_df)[0]
        proba = model.predict_proba(features_df)[0]
        confidence = round(proba[prediction] * 100, 2)

        result = 'Phishing URL' if prediction == 0 else 'Legitimate URL'
        response = {'url': url_to_check, 'result': result, 'confidence': confidence}

        if request.is_json:
            return jsonify(response)
        else:
            return render_template('index.html', prediction_text=f"{result} ({confidence}% confidence)", url=url_to_check)

    except Exception as e:
        response = {'url': url_to_check, 'result': f'Error in prediction: {e}', 'confidence': 0}
        return jsonify(response) if request.is_json else render_template('index.html', prediction_text=response['result'], url=url_to_check)

if __name__ == '__main__':
    app.run(debug=True)
