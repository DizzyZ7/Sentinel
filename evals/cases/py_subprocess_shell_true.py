import subprocess


def run(request):
    command = request.query_params["command"]
    return subprocess.run(command, shell=True, check=False)
