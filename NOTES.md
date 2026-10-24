# Setup notes (Windows)

- Python 3.12 via conda (`conda create -n safeagents python=3.12`)
- `pip install -r requirements.txt` fails on Windows: `requirements.txt` pins `onnxruntime==1.23.2`, but `markitdown` needs `onnxruntime<=1.20.1`.
- Workaround we used:

```
findstr /v /i "onnxruntime==" requirements.txt > requirements_fixed.txt
pip install -r requirements_fixed.txt
```

- Resulting version: `onnxruntime 1.20.1` (check yours with `pip show onnxruntime`)