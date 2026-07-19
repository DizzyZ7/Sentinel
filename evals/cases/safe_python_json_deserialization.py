import json


def restore(request):
    return json.loads(request.body)
