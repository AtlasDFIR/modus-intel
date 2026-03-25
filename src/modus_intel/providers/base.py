from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Optional

import httpx

from modus_intel.core.models import ProviderResult


class BaseProvider(ABC):
    registry: ClassVar[list[type["BaseProvider"]]] = []
    name: str = ""

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)

        if not getattr(cls, "__abstractmethods__", None) and cls.name:
            BaseProvider.registry.append(cls)

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