import requests


def proxy(request):
    url = request.query_params["url"]
    return requests.get(url)
