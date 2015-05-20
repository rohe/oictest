__author__ = 'roland'

NORMAL = "/_/_/_/normal"

IDMAP = {
    "rp-webfinger-url": NORMAL,
    "rp-webfinger-email": NORMAL,
    # ----------------------------------------
    "rp-disc-config": NORMAL,
    "rp-disc-jwks_uri": NORMAL,
    "rp-disc-faulty-issuer": "/_/_/isso/normal",
    # ----------------------------------------
    "rp-dynreg-0": NORMAL,
    # ----------------------------------------
    "rp-rtyp-code": NORMAL,
    "rp-rtyp-idt": NORMAL,
    "rp-rtyp-idt_token": NORMAL,
    # ----------------------------------------
    "rp-rmod-form": NORMAL,
    # ----------------------------------------
    "rp-tok-csbasic": NORMAL,
    "rp-tok-cspost": NORMAL,
    "rp-tok-csjwt": NORMAL,
    "rp-tok-pkjwt": NORMAL,
    # ----------------------------------------
    "rp-idt-asym_sig": "/RS256/_/_/normal",
    "rp-idt-sym_sig": "/HS256/_/_/normal",
    "rp-idt-ec_sig": "/ES256/_/_/normal",
    "rp-idt-invalid-asym_sig": "/RS256/_/idts/normal",
    "rp-idt-invalid-sym_sig": "/HS256/_/idts/normal",
    "rp-idt-invalid-ec_sig": "/ES256/_/idts/normal",
    "rp-idt-sigenc": "/HS256/RSA1_5:A128CBC-HS256/_/normal",
    "rp-idt-none": "/none/_/_/normal",
    # ----------------------------------------
    "rp-idt-iss": "/_/_/issi/normal",
    "rp-idt-sub": "/_/_/itsub/normal",
    "rp-idt-aud": "/_/_/aud/normal",
    "rp-idt-iat": "/_/_/iat/normal",
    "rp-idt-kid-absent": "/_/_/nokid1jwks/normal",
    "rp-idt-kid": "/_/_/nokidjwks/normal",
    "rp-idt-at_hash": "/_/_/ath/normal",
    "rp-idt-c_hash": "/_/_/ath/normal",
    # "rp-idt-epk": "",
    "rp-alg-rs256": "/RS256/_/idts/normal",
    "rp-alg-none": "/none/_/_/normal",
    "rp-alg-hs256": "/HS256/_/idts/normal",
    "rp-alg-es256": "/ES256/_/_/normal",
    "rp-idt-signenc": NORMAL,
    "rp-ui-hdr": NORMAL,
    "rp-ui-body": NORMAL,
    "rp-ui-not-query": NORMAL,
    "rp-bad-userinfo-sub": "/_/_/uisub/normal",
    "rp-ui-sign": NORMAL,
    "rp-ui-enc": NORMAL,
    "rp-ui-signenc": NORMAL,
    "rp-nonce-nocode": NORMAL,
    "rp-nonce-invalid": "/_/_/_/nonce/normal",
    "rp-scope-openid": NORMAL,
    "rp-scope": NORMAL,
    "rp-bad-iss-issuer": "/_/_/issi/normal",
    "rp-roll-op-sig": "/_/_/rotsig/normal",
    "rp-roll-rp-sig": NORMAL,
    "rp-roll-op-enc": "/_/_/rotenc/normal",
    "rp-roll-rp-enc": NORMAL,
    "rp-ruri-uns": NORMAL,
    "rp-ruri-sig": NORMAL,
    "rp-ruri-enc": NORMAL,
    "rp-ruri-sigenc": NORMAL,
    "rp-reqobj": NORMAL,
    "rp-clm-idt": NORMAL,
    # "rp-3rd-login": "",
    "rp-clm-aggreg": "/_/_/_/_/aggregate",
    "rp-clm-dist": "/_/_/_/_/distributed"
    # "rp-logout-init": "",
    # "rp-logout-received": "",
    # "rp-change-received": ""
}