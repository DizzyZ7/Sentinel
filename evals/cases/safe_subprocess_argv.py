import subprocess


def ping(request):
    host = request.query_params["host"]
    return subprocess.run(["ping", "-c", "1", host], shell=False, check=False)
