#!/usr/bin/env python3
"""Regenerate main/slh_dsa/slh_kat_vectors.h from the NIST ACVP vectors.

Usage:
    python3 tools/gen_slh_kat.py > main/slh_dsa/slh_kat_vectors.h

Downloads the FIPS 205 keyGen and sigGen internal projections from
usnistgov/ACVP-Server and emits the SLH-DSA-SHA2-128s subset as C arrays.
The sigGen file is ~38 MB, so the download is cached in the system temp dir.
"""

import json
import os
import sys
import tempfile
import urllib.request

BASE = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/"
        "gen-val/json-files")
KEYGEN_URL = f"{BASE}/SLH-DSA-keyGen-FIPS205/internalProjection.json"
SIGGEN_URL = f"{BASE}/SLH-DSA-sigGen-FIPS205/internalProjection.json"

PARAM_SET = "SLH-DSA-SHA2-128s"
N_KEYGEN = 3
# ACVP sigGen groups: (short tag, tgId selector predicate)
SIGGEN_GROUPS = [
    ("ext", lambda g: g["signatureInterface"] == "external" and g["preHash"] == "pure"),
    ("int", lambda g: g["signatureInterface"] == "internal"),
]


def fetch(url):
    cache = os.path.join(tempfile.gettempdir(),
                         "slh_kat_" + url.rsplit("/", 2)[-2] + ".json")
    if not os.path.exists(cache):
        print(f"downloading {url} ...", file=sys.stderr)
        urllib.request.urlretrieve(url, cache)
    return json.load(open(cache))


def carr(name, hexs, indent="    "):
    b = bytes.fromhex(hexs)
    out = [f"static const uint8_t {name}[{len(b)}] = {{"]
    line = indent
    for x in b:
        tok = f"0x{x:02X},"
        if len(line) + len(tok) > 96:
            out.append(line.rstrip())
            line = indent
        line += tok
    if line.strip():
        out.append(line.rstrip())
    out.append("};")
    return "\n".join(out)


def main():
    kg = fetch(KEYGEN_URL)
    sg = fetch(SIGGEN_URL)
    P = []

    P.append('''/*
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 *
 * NIST ACVP known-answer vectors for SLH-DSA-SHA2-128s.
 *
 * GENERATED FILE -- do not edit by hand.  Extracted verbatim from
 *   https://github.com/usnistgov/ACVP-Server
 *   gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json
 *   gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json
 * by tools/gen_slh_kat.py.
 *
 * The signing vectors are the deterministic ones (addrnd == NULL):
 *   - "external / pure" maps onto slh_sign()          (Jade's signing RPC path)
 *   - "internal"        maps onto slh_sign_internal()
 */

#ifndef _SLH_KAT_VECTORS_H_
#define _SLH_KAT_VECTORS_H_

#include <stddef.h>
#include <stdint.h>
''')

    g = [x for x in kg["testGroups"] if x.get("parameterSet") == PARAM_SET][0]
    sel = g["tests"][:N_KEYGEN]
    P.append(f"/* === {PARAM_SET} keyGen (ACVP tgId {g['tgId']}) === */\n")
    for i, t in enumerate(sel):
        for field, suffix in (("skSeed", "sk_seed"), ("skPrf", "sk_prf"),
                              ("pkSeed", "pk_seed"), ("sk", "sk"), ("pk", "pk")):
            P.append(carr(f"kat_kg{i}_{suffix}", t[field]))
        P.append("")

    P.append("""typedef struct {
    int tc_id;
    const uint8_t* sk_seed;
    const uint8_t* sk_prf;
    const uint8_t* pk_seed;
    const uint8_t* sk;
    const uint8_t* pk;
} slh_kat_keygen_t;
""")
    P.append("static const slh_kat_keygen_t slh_kat_keygen[] = {")
    for i, t in enumerate(sel):
        P.append(f"    {{ {t['tcId']}, kat_kg{i}_sk_seed, kat_kg{i}_sk_prf, "
                 f"kat_kg{i}_pk_seed, kat_kg{i}_sk, kat_kg{i}_pk }},")
    P.append("};\n")

    sigmeta = []
    for tag, pred in SIGGEN_GROUPS:
        cands = [x for x in sg["testGroups"]
                 if x.get("parameterSet") == PARAM_SET and x.get("deterministic") and pred(x)]
        g = cands[0]
        # shortest message keeps the generated header small
        t = min(g["tests"], key=lambda t: len(t["message"]))
        prehash = "/" + g["preHash"] if g["preHash"] != "none" else ""
        P.append(f"/* === {PARAM_SET} sigGen (ACVP tgId {g['tgId']}, "
                 f"{g['signatureInterface']}{prehash}, deterministic) === */\n")
        P.append(carr(f"kat_sig_{tag}_sk", t["sk"]))
        P.append(carr(f"kat_sig_{tag}_msg", t["message"]))
        if t.get("context"):
            P.append(carr(f"kat_sig_{tag}_ctx", t["context"]))
        P.append(carr(f"kat_sig_{tag}_expected", t["signature"]))
        P.append("")
        sigmeta.append((tag, t, g))

    P.append("""typedef struct {
    int tc_id;
    int external;            /* 1 -> slh_sign(), 0 -> slh_sign_internal() */
    const uint8_t* sk;
    const uint8_t* msg;
    size_t msg_len;
    const uint8_t* ctx;
    size_t ctx_len;
    const uint8_t* expected;
    size_t expected_len;
} slh_kat_siggen_t;
""")
    P.append("static const slh_kat_siggen_t slh_kat_siggen[] = {")
    for tag, t, g in sigmeta:
        ext = 1 if g["signatureInterface"] == "external" else 0
        ctx = f"kat_sig_{tag}_ctx" if t.get("context") else "NULL"
        ctx_len = len(t.get("context", "")) // 2
        P.append(f"    {{ {t['tcId']}, {ext}, kat_sig_{tag}_sk, kat_sig_{tag}_msg, "
                 f"{len(t['message']) // 2}, {ctx}, {ctx_len}, "
                 f"kat_sig_{tag}_expected, {len(t['signature']) // 2} }},")
    P.append("};\n")
    P.append("/* _SLH_KAT_VECTORS_H_ */\n#endif")
    print("\n".join(P))


if __name__ == "__main__":
    main()
