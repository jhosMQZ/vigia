"""Native analysis modules (M01–M10 + code analysis + code↔deploy correlation)."""
from __future__ import annotations

from vigia.core.module import Module
from vigia.modules.api import ApiModule
from vigia.modules.browser import BrowserModule
from vigia.modules.crawler import CrawlerModule
from vigia.modules.exposure import ExposureModule
from vigia.modules.frontend import FrontendModule
from vigia.modules.headers import HeadersModule
from vigia.modules.iac import IacModule
from vigia.modules.infra import InfraModule
from vigia.modules.injection import InjectionModule
from vigia.modules.recon import ReconModule
from vigia.modules.routes import RoutesModule
from vigia.modules.sast import SastModule
from vigia.modules.sca import ScaModule
from vigia.modules.secrets import SecretsModule

MODULES: dict[str, type[Module]] = {m.name: m for m in (
    ReconModule, CrawlerModule, BrowserModule, HeadersModule, ExposureModule, FrontendModule, InjectionModule, ApiModule, InfraModule,
    SastModule, SecretsModule, ScaModule, IacModule, RoutesModule)}
