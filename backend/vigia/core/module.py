"""Base class for native analysis modules."""
from __future__ import annotations

from typing import ClassVar

from vigia.core.context import ScanContext


class Module:
    name: ClassVar[str] = ""
    title: ClassVar[str] = ""
    phase: ClassVar[str] = "analysis"  # recon | discovery | analysis | correlation
    phases: ClassVar[tuple[str, ...]] = ()  # set when the module works in several phases (see run_phase)
    needs_target: ClassVar[bool] = False
    needs_source: ClassVar[bool] = False
    description: ClassVar[str] = ""

    def applicable(self, ctx: ScanContext) -> str | None:
        """Return None if the module can run, or the reason it is skipped."""
        if self.needs_target and ctx.http is None:
            return "sin objetivo desplegado en el alcance"
        if self.needs_source and ctx.source_dir is None:
            return "no se proporcionó código fuente"
        return None

    def active_phases(self) -> tuple[str, ...]:
        return self.phases or (self.phase,)

    async def run_phase(self, ctx: ScanContext, phase: str) -> None:
        await self.run(ctx)

    async def run(self, ctx: ScanContext) -> None:  # pragma: no cover - interface
        raise NotImplementedError
