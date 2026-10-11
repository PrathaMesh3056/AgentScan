# agentscan/_cli/__init__.py
#
# Internal CLI package — re-exports the app object and registers all command
# submodules by importing them (side-effect: each module calls @app.command()).

from agentscan._cli._shared import api_app, app, console

# Import command modules to register their @app.command() decorators
from agentscan._cli.commands import audit, heal, misc, scan, swarm  # noqa: F401

__all__ = ["app", "api_app", "console"]
