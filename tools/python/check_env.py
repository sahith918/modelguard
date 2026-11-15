import numpy as np
import onnx
import onnxruntime as ort
import torch

model = torch.nn.Sequential(torch.nn.Linear(4, 3), torch.nn.ReLU(), torch.nn.Linear(3, 2)).eval()
x = torch.randn(1, 4)
torch.onnx.export(model, x, "check.onnx", input_names=["x"], output_names=["y"], dynamo=False)

y = ort.InferenceSession("check.onnx").run(None, {"x": x.numpy()})[0]
diff = float(np.abs(y - model(x).detach().numpy()).max())
print("PASS" if diff < 1e-5 else "FAIL")