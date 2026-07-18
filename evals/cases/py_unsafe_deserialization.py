import pickle


def restore(request):
    return pickle.loads(request.body)
