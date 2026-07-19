def execute_script(request):
    script = request.body
    exec(script)
