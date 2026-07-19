import requests


def healthcheck():
    return requests.get("https://example.com/health")
