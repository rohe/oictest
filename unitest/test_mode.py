from oic.oic import OIDCONF_PATTERN
from oictest.mode import extract_mode, mode2path

__author__ = 'roland'


def test_extract_mode():
    mod, path = extract_mode("test_id")
    assert mod == {"test_id": "test_id"}
    assert path == ""

    mod, path = extract_mode(OIDCONF_PATTERN % "test_id")
    assert mod == {"test_id": "test_id"}
    assert path == '.well-known/openid-configuration'

    mod, path = extract_mode("/test_id/_/_/_/normal")
    assert mod == {"test_id": "test_id", "claims": ["normal"]}
    assert path == ''

    mod, path = extract_mode("/test_id/_/_/_/normal/token")
    assert mod == {"test_id": "test_id", "claims": ["normal"]}
    assert path == 'token'

    mod, path = extract_mode(
        "/test_id/RS256/RSA1_5:A128CBC-HS256/iat/normal/token")
    assert mod == {'behavior': ['iat'],
                   'enc_alg': 'RSA1_5',
                   'enc_enc': 'A128CBC-HS256',
                   'sign_alg': 'RS256',
                   'claims': ['normal'],
                   'test_id': 'test_id'}
    assert path == 'token'

    mod, path = extract_mode(
        "/test_id/RS256/RSA1_5:A128CBC-HS256/iat,issi/normal,aggregated/token")
    assert mod == {'behavior': ['iat', 'issi'],
                   'enc_alg': 'RSA1_5',
                   'enc_enc': 'A128CBC-HS256',
                   'sign_alg': 'RS256',
                   'claims': ['normal', 'aggregated'],
                   'test_id': 'test_id'}
    assert path == 'token'


def test_mode2path():
    path = mode2path({"test_id": "test_id"})
    assert path == "test_id/_/_/_/normal"

    path = mode2path({"test_id": "test_id", "claims": ["aggregated"]})
    assert path == "test_id/_/_/_/aggregated"

    path = mode2path({'behavior': ['iat', 'issi'], 'enc_alg': 'RSA1_5',
                      'enc_enc': 'A128CBC-HS256', 'sign_alg': 'RS256',
                      'claims': ['normal', 'aggregated'], 'test_id': 'test_id'})
    assert path == ("test_id/RS256/RSA1_5:A128CBC-HS256/iat,issi/"
                    "normal,aggregated")


if __name__ == "__main__":
    test_mode2path()