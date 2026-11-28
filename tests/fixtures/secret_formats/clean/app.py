# Clean synthetic fixture: values come from the environment.
import os

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
