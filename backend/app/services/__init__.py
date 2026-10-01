"""The service layer between the API routers and the domain modules (Bible Ch13 step 2, Architecture §25).

    routers (app.api.v1)  ->  services  ->  domain (scoring, cri, mitre, explainability, alerts)  ->  database / models

Routers only marshal requests and responses; every query, check and
decision is here. Services never import FastAPI, and never import label code
(N5): they read decisions from PostgreSQL and score through the runtimes the
lifespan handler loaded once (HCEA §8). Nothing here writes an alert row
(N58); the only writes are analyst accounts and their audit rows.
"""
