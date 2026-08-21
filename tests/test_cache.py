import time

from modus_intel.core.cache import Cache


def make_cache(tmp_path) -> Cache:
    return Cache(db_path=tmp_path / "cache.db")


class TestCache:
    def test_get_missing_returns_none(self, tmp_path):
        cache = make_cache(tmp_path)
        assert cache.get("nope") is None

    def test_set_and_get_roundtrip(self, tmp_path):
        cache = make_cache(tmp_path)
        cache.set("k", {"provider": "virustotal", "score": 42}, ttl_seconds=60)
        assert cache.get("k") == {"provider": "virustotal", "score": 42}

    def test_upsert_replaces_value(self, tmp_path):
        cache = make_cache(tmp_path)
        cache.set("k", {"score": 1}, ttl_seconds=60)
        cache.set("k", {"score": 2}, ttl_seconds=60)
        assert cache.get("k") == {"score": 2}

    def test_expired_entry_returns_none(self, tmp_path, monkeypatch):
        cache = make_cache(tmp_path)
        cache.set("k", {"score": 1}, ttl_seconds=10)

        future = time.time() + 3600
        monkeypatch.setattr(time, "time", lambda: future)
        assert cache.get("k") is None

    def test_purge_expired_removes_only_expired(self, tmp_path, monkeypatch):
        cache = make_cache(tmp_path)
        cache.set("old", {"score": 1}, ttl_seconds=10)
        cache.set("fresh", {"score": 2}, ttl_seconds=7200)

        future = time.time() + 3600
        monkeypatch.setattr(time, "time", lambda: future)

        purged = cache.purge_expired()
        assert purged == 1
        assert cache.get("fresh") == {"score": 2}

    def test_make_key_format(self):
        key = Cache.make_key("virustotal", "ip", "8.8.8.8")
        assert key == "virustotal:ip:8.8.8.8"
