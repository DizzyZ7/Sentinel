def download(request):
    path = request.query_params["path"]
    return open(path, "rb")
