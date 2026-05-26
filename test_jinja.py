import jinja2
try:
    env = jinja2.Environment()
    print(f"Jinja2 version: {jinja2.__version__}")
    template = env.from_string("{{ x | tojson }}")
    print(template.render(x={"a": 1, "b": "c'd"}))
except Exception as e:
    print(f"Error: {e}")
