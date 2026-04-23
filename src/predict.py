"""Loads the trained model and label encoder, and provides a method to predict the label of a flow based on its features
along with the confidence of the prediction."""

import joblib
import numpy as np
import os
import pandas as pd
import time
import shap

class Predictor:

    def __init__(self, model_path = 'models/nids.pkl', encoder_path = 'models/label_encoder.pkl'):

        """Initializes the Predictor by loading the trained model and label encoder from disk."""

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at {model_path}. Please train the model first.")
        if not os.path.exists(encoder_path):
            raise FileNotFoundError(f"Label encoder file not found at {encoder_path}. Please train the model first.")
        
        print("Loading model and label encoder...")
        self.model = joblib.load(model_path)
        self.encoder = joblib.load(encoder_path)
        print("Model and label encoder loaded successfully.")

        self.explainer = shap.TreeExplainer(self.model)
        self.feature_names = self.model.feature_names_in_

    def explain(self, features, predicted_label):
        features_array = np.array(features).reshape(1, -1)
        shap_values = self.explainer.shap_values(features_array)

        class_idx = list(self.encoder.classes_).index(predicted_label)
        feature_shap = shap_values[0, :, class_idx]

        contributions = sorted(
            zip(self.feature_names, features, feature_shap),
            key = lambda x: abs(x[2]),
            reverse = True
        )

        print(f"\n[SHAP EXPLANATION] Top contributors for {predicted_label}:")
        for fname, fval, shap_val in contributions[:10]:
            direction = 'POS+' if shap_val > 0 else 'NEG-'
            print(f"  {direction} {fname:<30} value={fval:>10.2f}  impact={shap_val:>+.4f}")
        print()

    def predict(self, features):

        """Predicts the label of a flow based on its features using the loaded model."""

        try:
            features_array = np.nan_to_num(
                np.array(features, dtype = float),
                nan = 0.0,
                posinf = 0.0,
                neginf = 0.0
            ).reshape(1, -1)

            #Get feature names from model
            features_names = self.model.feature_names_in_
            features_df = pd.DataFrame(features_array, columns = features_names)


            start = time.perf_counter()
            probabilitity = self.model.predict_proba(features_df)[0]
            prediction_time = (time.perf_counter() - start) * 1000

            classes = self.encoder.classes_
            #Detection threshold
            benign_idx = list(classes).index('BENIGN')
            benign_prob = probabilitity[benign_idx]

            max_idx = np.argmax(probabilitity)
            label = classes[max_idx]
            confidence = probabilitity[max_idx] * 100

            if benign_prob < 0.50:
                attack_probs = [(classes[i], probabilitity[i])
                                for i in range (len(classes))
                                if classes[i] != 'BENIGN']
                
                attack_probs.sort(key = lambda x: x[1], reverse = True)
                top_attack = attack_probs[0]

                if top_attack[1] > 0.50:
                    return top_attack[0], top_attack[1] * 100
                else:
                    return 'BENIGN', benign_prob * 100 #Return as benign if model is not at least 50% confident in its attack type

            return label, confidence
        except Exception as e:
            print(f"Error during prediction: {e}")
            return "Error", 0.0
        
    def is_attack(self, label):
        """Determines if the predicted label indicates an attack or benign flow."""
        if label == 'Error':
            return False
        return label != 'BENIGN'