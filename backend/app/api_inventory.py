"""API inventory helpers.

Control: API-001 (API Security)

This module builds a code-generated inventory of FastAPI routes so the application can
expose and export an up-to-date API catalog without any frontend changes.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.routing import APIRoute


def build_api_inventory(app: FastAPI) -> list[dict[str, object]]:
    inventory: list[dict[str, object]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        inventory.append(
            {
                "path": route.path,
                "methods": sorted(method for method in route.methods or []),
                "name": route.name,
                "response_model": getattr(route, "response_model", None).__name__ if getattr(route, "response_model", None) else None,
                "include_in_schema": route.include_in_schema,
            }
        )
    inventory.sort(key=lambda item: (str(item["path"]), str(item["name"])))
    return inventory
