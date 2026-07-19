import httpx


def proxy(request):
    target = request.query_params["target"]
    return httpx.get(target)
