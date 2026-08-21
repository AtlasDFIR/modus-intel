from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import ClassVar, Optional

import httpx

from modus_intel.core.models import ProviderResult


class BaseProvider(ABC):
    """
    Base class for enrichment providers.

    Concrete subclasses that define a ``name`` are automatically added to
    ``BaseProvider.registry`` at class-creation time. The CLI instantiates
    every registered provider, so adding a new provider only requires
    creating the subclass and importing it in ``providers/__init__.py``.
    """

    registry: ClassVar[list[type["BaseProvider"]]] = []
    name: str = ""

    # Environment variable holding this provider's API key. Used to warn the
    # user when a provider is skipped because no key is configured.
    env_var: ClassVar[str] = ""

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)

        if not getattr(cls, "__abstractmethods__", None) and cls.name:
            BaseProvider.registry.append(cls)

    def is_configured(self) -> bool:
        """Whether this provider has the credentials it needs to run."""
        if not self.env_var:
            return True
        return bool(os.getenv(self.env_var))

    @abstractmethod
    def supports(self, indicator_type: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def lookup_async(
        self,
        indicator: str,
        indicator_type: str,
        client: httpx.AsyncClient,
    ) -> Optional[ProviderResult]:
        """
        Async lookup hook. Providers should override this.

        indicator:
            The normalized IOC value.

        indicator_type:
            The detected IOC type (e.g. ip, domain, url, md5, sha1, sha256).

        client:
            Shared async HTTP client used for provider requests.
        """
        raise NotImplementedError
