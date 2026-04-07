"""Loads the trained model and label encoder, and provides a method to predict the label of a flow based on its features
along with the confidence of the prediction."""

import joblib
import numpy as np
import os
import pandas as pd

class Predictor:

    def __init__(self, model_path = 'models/nids_model.pkl', encoder_path = 'models/label_encoder.pkl'):

        """Initializes the Predictor by loading the trained model and label encoder from disk."""

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at {model_path}. Please train the model first.")
        if not os.path.exists(encoder_path):
            raise FileNotFoundError(f"Label encoder file not found at {encoder_path}. Please train the model first.")
        
        print("Loading model and label encoder...")
        self.model = joblib.load(model_path)
        self.encoder = joblib.load(encoder_path)
        print("Model and label encoder loaded successfully.")

    def predict(self, features):

        """Predicts the label of a flow based on its features using the loaded model."""

        try:
            features_array = np.nan_to_num(
                np.array(features, dtype = float),
                nan = 0.0,
                posinf = 0.0,
                neginf = 0.0
            )

            #Get feature names from model
            features_names = self.model.feature_names_in_
            features_df = pd.DataFrame([features_array], columns = features_names)

            prediction = self.model.predict(features_df)
            probabilitity = self.model.predict_proba(features_df)

            label = self.encoder.inverse_transform(prediction)[0]
            confidence = np.max(probabilitity) * 100

            return label, confidence
        except Exception as e:
            print(f"Error during prediction: {e}")
            return "Error", 0.0
        
    def is_attack(self, label):
        """Determines if the predicted label indicates an attack or benign flow."""
        return label != 'BENIGN'