import os


def run(request):
    command = request.query_params["command"]
    return os.system(command)
