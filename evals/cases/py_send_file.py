from flask import send_file


def download(request):
    filename = request.query_params["filename"]
    return send_file(filename)
