from modus_intel.core.detect import (
    clean_ioc,
    detect_ioc_type,
    normalize_ioc,
    prepare_ioc,
    refang,
)


class TestDetectIocType:
    def test_ipv4(self):
        assert detect_ioc_type("8.8.8.8") == "ip"

    def test_ipv6(self):
        assert detect_ioc_type("2001:4860:4860::8888") == "ip"

    def test_domain(self):
        assert detect_ioc_type("example.com") == "domain"

    def test_subdomain(self):
        assert detect_ioc_type("mail.corp.example.com") == "domain"

    def test_url_http(self):
        assert detect_ioc_type("http://example.com/path") == "url"

    def test_url_https(self):
        assert detect_ioc_type("https://example.com") == "url"

    def test_md5(self):
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_sha1(self):
        assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"

    def test_sha256(self):
        assert (
            detect_ioc_type(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            == "sha256"
        )

    def test_garbage_is_unknown(self):
        assert detect_ioc_type("not a real indicator!!") == "unknown"

    def test_hash_with_wrong_length_is_unknown(self):
        assert detect_ioc_type("abcdef1234") == "unknown"

    def test_weird_scheme_is_not_url(self):
        # A bare host:port must not classify as a URL just because
        # urlparse treats the host as a scheme.
        assert detect_ioc_type("example.com:8080") != "url"


class TestRefang:
    def test_hxxp(self):
        assert refang("hxxp://evil.com") == "http://evil.com"

    def test_hxxps(self):
        assert refang("hxxps://evil.com") == "https://evil.com"

    def test_bracket_dot_domain(self):
        assert refang("evil[.]com") == "evil.com"

    def test_bracket_dot_ip(self):
        assert refang("192.168[.]1[.]1") == "192.168.1.1"

    def test_paren_dot(self):
        assert refang("evil(.)com") == "evil.com"

    def test_dot_word(self):
        assert refang("evil[dot]com") == "evil.com"

    def test_combined(self):
        assert refang("hxxps://evil[.]com/payload") == "https://evil.com/payload"

    def test_clean_input_unchanged(self):
        assert refang("https://example.com/a?b=C") == "https://example.com/a?b=C"


class TestCleanAndNormalize:
    def test_strips_quotes(self):
        assert clean_ioc('"evil.com"') == "evil.com"
        assert clean_ioc("'8.8.8.8'") == "8.8.8.8"

    def test_domain_lowercased(self):
        assert normalize_ioc("EVIL.COM", "domain") == "evil.com"

    def test_hash_lowercased(self):
        assert (
            normalize_ioc("D41D8CD98F00B204E9800998ECF8427E", "md5")
            == "d41d8cd98f00b204e9800998ecf8427e"
        )

    def test_url_host_lowercased_path_preserved(self):
        assert (
            normalize_ioc("HTTPS://EVIL.COM/CaseSensitive/Path", "url")
            == "https://evil.com/CaseSensitive/Path"
        )


class TestPrepareIoc:
    def test_defanged_url_pipeline(self):
        value, ioc_type = prepare_ioc("hxxp://Evil[.]com/malware.exe")
        assert ioc_type == "url"
        assert value == "http://evil.com/malware.exe"

    def test_quoted_domain_pipeline(self):
        value, ioc_type = prepare_ioc('"EVIL.COM"')
        assert ioc_type == "domain"
        assert value == "evil.com"

    def test_defanged_ip_pipeline(self):
        value, ioc_type = prepare_ioc("45.155.205[.]233")
        assert ioc_type == "ip"
        assert value == "45.155.205.233"

    def test_unknown_pipeline(self):
        _, ioc_type = prepare_ioc("definitely not an ioc")
        assert ioc_type == "unknown"
