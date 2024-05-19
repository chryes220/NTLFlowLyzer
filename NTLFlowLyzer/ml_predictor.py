from .model import Model

class MLPredictor:
    def __init__(self, model_path: str, model_name: str):
        self.model = Model(model_name, model_path)
        

    def predict(self, data):
        return self.model.predict(data)