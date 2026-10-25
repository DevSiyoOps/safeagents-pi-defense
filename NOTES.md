# Setup notes

- Python 3.12 via conda (`conda create -n safeagents python=3.12`)

## Windows only: onnxruntime conflict

- `pip install -r requirements.txt` fails on Windows: `requirements.txt` pins `onnxruntime==1.23.2`, but `markitdown` needs `onnxruntime<=1.20.1` on win32.
- Workaround we used:

```
findstr /v /i "onnxruntime==" requirements.txt > requirements_fixed.txt
pip install -r requirements_fixed.txt
```

- Resulting version on Windows: `onnxruntime 1.20.1` (check with `pip show onnxruntime`).

## Mac/Linux

- Install normally, no workaround needed: `pip install -r requirements.txt` (installs onnxruntime 1.23.2).
- The version difference between machines is fine, since onnxruntime only comes in through `magika`, not the agents.