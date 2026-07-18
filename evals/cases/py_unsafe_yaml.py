import yaml


def parse(request):
    return yaml.load(request.body)
