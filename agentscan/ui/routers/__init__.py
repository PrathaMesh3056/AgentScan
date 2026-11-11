# agentscan/ui/routers/__init__.py
#
# Aggregates and registers all APIRouter modules for the AgentScan dashboard.

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI


def register_all_routers(app: FastAPI) -> None:
    """Include all UI APIRouter instances on the FastAPI app."""
    from agentscan.ui.routers import (
        audit,
        compliance,
        events,
        features,
        gateway,
        heal,
        identity,
        mcp,
        reports,
        scan,
        sentinel,
        swarms,
        telemetry,
    )

    routers = [
        scan.router,
        events.router,
        features.router,
        gateway.router,
        heal.router,
        audit.router,
        swarms.router,
        sentinel.router,
        identity.router,
        compliance.router,
        mcp.router,
        reports.router,
        telemetry.router,
    ]

    for router in routers:
        app.include_router(router)
