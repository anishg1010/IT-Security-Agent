"""Show empirically why the current eval set cannot train confidence weights."""
import numpy as np
from sklearn.linear_model import LogisticRegression

# Reconstruct the Week 2 feature space for the 25 cases.
# Columns: [match_path, version_specificity, input_source, vendor_known]
# match_path: 1.0 = CPE, 0.5 = fallback
# Every case came from an SBOM (input_source = 1.0).

rows, y = [], []

# 11 true_positive: clean CPE, exact version, known vendor -> fires, correct
for _ in range(11):
    rows.append([1.0, 1.0, 1.0, 1.0]); y.append(1)

# 5 hard_positive: CPE path after alias resolution -> fires, correct
for _ in range(5):
    rows.append([1.0, 1.0, 1.0, 1.0]); y.append(1)

# 2 fallback_positive: fallback path -> fires, correct
for _ in range(2):
    rows.append([0.5, 0.6, 1.0, 1.0]); y.append(1)

# 4 true_negative + 2 boundary: never fire, so they produce NO confidence score
# at all. They are absent from the calibration data entirely.

X = np.array(rows); y = np.array(y)

print(f"Fired matches available for fitting : {len(y)}")
print(f"Distinct labels present            : {set(y.tolist())}")
print(f"Negative examples (wrong matches)  : {(y == 0).sum()}")
print()

try:
    clf = LogisticRegression().fit(X, y)
    print("fit succeeded:", clf.coef_)
except ValueError as e:
    print(f"LogisticRegression refuses to fit:\n  {e}")

print()
print("The non-firing cases (TN, boundary) produce no confidence score,")
print("so they cannot appear in a calibration dataset. The 18 that do fire")
print("are ALL correct. There is no error signal anywhere in the data.")
