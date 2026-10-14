"""Offline analysis of detector results against dataset ground truth.

The pipeline has two halves. A dataset loader (analysis.datasets) turns a
dataset's own label files into the common label format (analysis.schema).
Everything after that, ground-truth construction (analysis.groundtruth) and
evaluation (analysis.evaluate), depends only on the common format, so adding
a dataset means adding a loader and nothing else.
"""
