"""Make a synthetic query log with known benign and extraction-like clients.

Run from the project folder:   python tools/python/make_monitor_data.py
Writes data/reference.csv and data/queries.csv

Clients:
  benign_0..4        200 normal queries over an hour            -> expect nothing
  heavy_benign       3000 normal queries in 20 minutes          -> expect rate_limit (warning) only
  extractor          2000 random probes in 5 minutes            -> expect rate_limit + distribution_drift
  stealth_extractor  300 random probes spread over an hour      -> expect distribution_drift only
"""
import argparse
import os

import numpy as np


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--dim", type=int, default=8)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()

    rng = np.random.default_rng(a.seed)
    d = a.dim
    os.makedirs(a.out, exist_ok=True)

    ref = rng.normal(size=(2000, d))
    np.savetxt(os.path.join(a.out, "reference.csv"), ref, delimiter=",", fmt="%.5f")

    rows = []

    def add(client, n, duration, gen):
        ts = rng.uniform(0, duration, size=n)
        X = gen(n)
        for t, x in zip(ts, X):
            rows.append((t, client, x))

    normal = lambda n: rng.normal(size=(n, d))
    uniform = lambda n: rng.uniform(-4, 4, size=(n, d))

    for i in range(5):
        add(f"benign_{i}", 200, 3600, normal)
    add("heavy_benign", 3000, 1200, normal)
    add("extractor", 2000, 300, uniform)
    add("stealth_extractor", 300, 3600, uniform)

    rows.sort(key=lambda r: r[0])
    with open(os.path.join(a.out, "queries.csv"), "w") as f:
        for t, client, x in rows:
            f.write(f"{client},{t:.3f}," + ",".join(f"{v:.4f}" for v in x) + "\n")
    print(f"queries={len(rows)} clients=8 dim={d}")
    print(f"written to {a.out}\\")


if __name__ == "__main__":
    main()
