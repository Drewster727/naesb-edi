from fastapi import Request

from app.crypto.gpg_wrapper import GpgService
from app.partners import PartnerRegistry
from app.settings import Settings
from app.sinks.base import Sink
from app.tracking.repository import MessageTracker


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_partners(request: Request) -> PartnerRegistry:
    return request.app.state.partners


def get_gpg(request: Request) -> GpgService:
    return request.app.state.gpg


def get_fingerprints(request: Request) -> dict[str, str]:
    return request.app.state.fingerprints


def get_tracker(request: Request) -> MessageTracker:
    return request.app.state.tracker


def get_sinks(request: Request) -> list[Sink]:
    return request.app.state.sinks
