import pickle


def restore(request):
    return pickle.load(request.body)
