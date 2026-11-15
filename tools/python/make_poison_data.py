"""Make a synthetic 'embeddings' dataset with a known set of poisoned samples.

Run from the project folder:   python tools/python/make_poison_data.py
Writes data/embeddings.npy, data/labels.npy, data/poison_mask.npy

The poisoned samples are labelled as class 0 and shifted along one hidden
direction, which is how a backdoor trigger tends to look in feature space.
This is a simulation for measuring the detector, not a real attack.
"""
import argparse
import os

import numpy as np


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--classes", type=int, default=4)
    ap.add_argument("--per-class", type=int, default=500)
    ap.add_argument("--dim", type=int, default=32)
    ap.add_argument("--poison-rate", type=float, default=0.10, help="share of class 0 that is poisoned")
    ap.add_argument("--shift", type=float, default=6.0, help="how far poisoned samples move (in std devs)")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    rng = np.random.default_rng(a.seed)
    means = rng.normal(0.0, 3.0, size=(a.classes, a.dim))

    xs, ys, masks = [], [], []
    for c in range(a.classes):
        x = rng.normal(means[c], 1.0, size=(a.per_class, a.dim))
        m = np.zeros(a.per_class, dtype=np.uint8)
        if c == 0:
            k = int(round(a.poison_rate * a.per_class))
            u = rng.normal(size=a.dim)
            u /= np.linalg.norm(u)
            idx = rng.choice(a.per_class, size=k, replace=False)
            x[idx] += a.shift * u
            m[idx] = 1
        xs.append(x)
        ys.append(np.full(a.per_class, c, dtype=np.int64))
        masks.append(m)

    X = np.concatenate(xs).astype(np.float32)
    Y = np.concatenate(ys)
    M = np.concatenate(masks)
    perm = rng.permutation(len(Y))
    X, Y, M = X[perm], Y[perm], M[perm]

    os.makedirs(a.out, exist_ok=True)
    np.save(os.path.join(a.out, "embeddings.npy"), X)
    np.save(os.path.join(a.out, "labels.npy"), Y)
    np.save(os.path.join(a.out, "poison_mask.npy"), M)
    print(f"samples={len(Y)} dim={a.dim} classes={a.classes} poisoned={int(M.sum())}")
    print(f"written to {a.out}\\")


if __name__ == "__main__":
    main()
