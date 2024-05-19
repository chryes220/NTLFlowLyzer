import joblib
import warnings

warnings.filterwarnings('ignore', category=UserWarning, module='xgboost')

class Model():
  def __init__(self, name: str, path: str):
    self.name = name
    self.model = joblib.load(path)

  def predict(self, data):
    return self.model.predict(data)