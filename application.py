from flask import Flask, render_template, request
import joblib
import numpy as np

# Load the trained model
model = joblib.load('random_forest_model.pkl')

# Mapping PCA components back to original feature names
pca_feature_mapping = {
    'PC1': 'Idle Std', 'PC2': 'Active Max', 'PC3': 'Active Std', 'PC4': 'Active Mean',
    'PC5': 'min_seg_size_forward', 'PC6': 'act_data_pkt_fwd', 'PC7': 'Init_Win_bytes_forward',
    'PC8': 'Init_Win_bytes_backward', 'PC9': 'Down/Up Ratio', 'PC10': 'URG Flag Count',
    'PC11': 'ACK Flag Count', 'PC12': 'PSH Flag Count', 'PC13': 'RST Flag Count', 'PC14': 'FIN Flag Count',
    'PC15': 'Min Packet Length', 'PC16': 'Bwd Packets/s', 'PC17': 'Bwd Header Length',
    'PC18': 'Fwd Header Length', 'PC19': 'Fwd URG Flags', 'PC20': 'Fwd PSH Flags',
    'PC21': 'Bwd IAT Max', 'PC22': 'Bwd IAT Std', 'PC23': 'Bwd IAT Mean', 'PC24': 'Bwd IAT Total',
    'PC25': 'Fwd IAT Min', 'PC26': 'Flow IAT Min', 'PC27': 'Flow IAT Std', 'PC28': 'Flow IAT Mean',
    'PC29': 'Flow Packets/s', 'PC30': 'Flow Bytes/s', 'PC31': 'Bwd Packet Length Min',
    'PC32': 'Bwd Packet Length Max', 'PC33': 'Fwd Packet Length Mean', 'PC34': 'Fwd Packet Length Min',
    'PC35': 'Fwd Packet Length Max',
}

important_features = list(pca_feature_mapping.keys())

# Initialize Flask app
application = Flask(__name__)

app=application

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Retrieve feature values from the form
        feature_values = {}
        for feature in important_features:
            feature_values[feature] = request.form.get(feature, "0")  # Default value is "0"

        try:
            # Convert input values to float
            feature_array = np.array([float(feature_values[feature]) for feature in important_features]).reshape(1, -1)

            # Predict intrusion
            prediction = model.predict(feature_array)

            # Display results
            if prediction[0] == 1:
                result = "⚠️ Intrusion Detected!"
                result_class = "error"
            else:
                result = "✅ No Intrusion Detected!"
                result_class = "success"
        except ValueError:
            result = "Please enter valid numerical values for all features."
            result_class = "warning"
        
        return render_template('index.html', pca_feature_mapping=pca_feature_mapping, result=result, result_class=result_class)

    return render_template('index.html', pca_feature_mapping=pca_feature_mapping)

if __name__ == '__main__':
    app.run(host="0.0.0.0")