import yaml


def parse(request):
    return yaml.safe_load(request.body)
