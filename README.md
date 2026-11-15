# ModelGuard

A small C++20 toolkit that guards the three stages of a machine-learning model's life:

| Stage | Command | What it does |
|---|---|---|
| Model file | `keygen`, `sign`, `verify` | Ed25519 signatures (libsodium) detect any change to a model file |
| Training data | `scan` | Spectral-signature detector flags poisoned samples in embeddings |
| Serving | `monitor` | Flags model-extraction behaviour in a query log (rate + distribution drift) |

All detectors report through one `Finding` type, as text or JSON (`--json`).
Exit code `0` = clean, `2` = a critical finding, `1` = error. That makes it usable in CI.

## Build (Windows, Visual Studio Build Tools + vcpkg)

```
set VCPKG_ROOT=C:\vcpkg
cmake --preset default
cmake --build --preset debug
ctest --preset debug
```
Libraries (see `vcpkg.json`): nlohmann-json, spdlog, cli11, libsodium, gtest.
The preset expects vcpkg in `C:/vcpkg`; edit `CMakePresets.json` if yours is elsewhere.

## Try it

**Integrity**
```
build\Debug\modelguard.exe keygen
build\Debug\modelguard.exe sign model.onnx --key modelguard.key
build\Debug\modelguard.exe verify model.onnx --manifest model.onnx.mg.json --pub modelguard.pub
```
Keep `modelguard.key` secret and distribute `modelguard.pub` separately from the model.

**Poison scan** (synthetic data with known answers; needs numpy)
```
python tools/python/make_poison_data.py
build\Debug\modelguard.exe scan data\embeddings.npy data\labels.npy --truth data\poison_mask.npy
```

**Extraction monitor**
```
python tools/python/make_monitor_data.py
build\Debug\modelguard.exe monitor data\queries.csv --reference data\reference.csv
```

## Measured results (synthetic data)

Poison scan, 4 classes x 500 samples, 32 dimensions, poison in class 0:

| Poisoned share | Shift (std devs) | Precision | Recall |
|---|---|---|---|
| 10% | 6 | 1.00 | 1.00 |
| 10% | 4 | 1.00 | 0.44 |
| 10% | 3 | 1.00 | 0.10 |
| 10% | 2 | - | 0.00 |
| 2% | 6 | 0.90 | 0.90 |
| 30% | 6 | 1.00 | 0.28 |

Monitor, 8 simulated clients: the 5 normal clients are not flagged; a heavy but legitimate
client gets a rate warning only; a fast random-probing client gets rate + drift; a slow
random-probing client is caught by drift alone.

## Limitations (please read)

- The spectral detector only works when poisoned samples are well separated from clean ones in
  feature space, and loses recall when poison is a large share of a class. An adaptive attacker
  can evade it.
- The monitor sees only what the query log contains. Drift detection needs a representative
  reference set, and heavy legitimate users trigger the rate warning (use `--allow`).
- Results above come from synthetic data, not real backdoored models.
- Signatures protect the model file only if the public key reaches the verifier by a separate,
  trusted channel.

## Not built yet

Per-tensor hashing and ONNX graph auditing, activation-clustering and k-NN poison detectors,
boundary-probing and PRADA-style extraction detectors, and a live HTTP gateway.
