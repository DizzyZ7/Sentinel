def calculate(request):
    expression = request.query_params["expression"]
    return eval(expression)
