"""Pydantic request and response models for the /api/v1 routes (Bible Ch13, Architecture §25).

Two rules hold in every model here. The anomaly score and the CRI are two
fields, never one, and neither is described as a probability (N20, N34).
List responses carry ``total``, ``limit``, ``offset`` and the server-side cap
``max_limit`` (HCEA §13).
"""
