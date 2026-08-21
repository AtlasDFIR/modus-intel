# Importing the provider modules triggers BaseProvider.__init_subclass__,
# which populates BaseProvider.registry. The CLI builds its provider list
# from that registry, so a new provider only needs a subclass and an import
# here to be picked up.
from .abuseipdb import AbuseIPDBProvider
from .greynoise import GreyNoiseProvider
from .urlhaus import URLHausProvider
from .virustotal import VirusTotalProvider

__all__ = [
    "AbuseIPDBProvider",
    "GreyNoiseProvider",
    "URLHausProvider",
    "VirusTotalProvider",
]
