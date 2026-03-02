import joblib
import numpy as np
from skl2onnx import to_onnx
from skl2onnx.common.data_types import FloatTensorType

# load the model
model = joblib.load('randomforest.joblib')

# define input contract
num_features = 12
initial_type = [('float_input', FloatTensorType([None, num_features]))]

# zipmap shd be false for chrome
options = {type(model): {'zipmap': False}}
onx = to_onnx(model, initial_types=initial_type, options=options)

# save file to extension folder
with open("../../extension/model/antiphish_model.onnx", "wb") as f:
    f.write(onx.SerializeToString())

print("Success! Model exported to extension/model/antiphish_model.onnx")