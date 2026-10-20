#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of the openScale S400 fork (tools/s400_cloud). Needs token_extractor.py next to it; see README.md.
"""scale_users.py - lista los usuarios de una bascula Xiaomi desde la nube:
slot (accountCode = duid), MIID (accountId), userType y nombre.

Reutiliza el login de token_extractor.py (mismo directorio, sin modificarlo).
Solo lectura: no escribe archivos, no crea/borra/edita perfiles.
Imprime unicamente: nombre, accountCode, accountId, type. Nunca fecha de
nacimiento, estatura ni sexo.

Uso:
  python scale_users.py                 # interactivo (p=password / q=QR)
  python scale_users.py -s de           # fija servidor
  python scale_users.py --did blt.3.xxx # fija dispositivo
  python scale_users.py --probe         # imprime SOLO la forma (claves/tipos) de las respuestas
  python scale_users.py --selftest      # prueba offline de cripto/firma (sin red)
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import time

import requests

_ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
_ap.add_argument("-s", "--server", default=None, help="cn|de|us|ru|tw|sg|in|i2 (vacio=todos)")
_ap.add_argument("--did", default=None, help="did del dispositivo (si no, se detectan basculas)")
_ap.add_argument("--probe", action="store_true", help="solo forma de respuestas, sin valores")
_ap.add_argument("--selftest", action="store_true", help="prueba offline, sin red ni login")
MINE = _ap.parse_args()

# token_extractor parsea sys.argv al importarse: lo dejamos limpio.
sys.argv = [sys.argv[0]]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import token_extractor as te  # noqa: E402

SERVERS = te.SERVERS
HLTH_REGIONS = ("de", "i2", "ru", "sg", "us")
PATH_LIST = "/eco/scale/account/list"
PROXY_PATH = "/app/v1/eco/api_proxy"


# ---------- utilidades ----------
def shape(o):
    """Forma de un JSON: claves y tipos, nunca valores."""
    if isinstance(o, dict):
        return {k: shape(v) for k, v in o.items()}
    if isinstance(o, list):
        return {"_list_len": len(o), "_item": shape(o[0]) if o else None}
    return type(o).__name__


def hlth_base(server):
    if server in ("", "cn"):
        return "https://hlth.io.mi.com"
    if server in HLTH_REGIONS:
        return "https://%s.hlth.io.mi.com" % server
    return None


def hlth_request(c, base, path, data_str):
    """Replica el cliente Mi Fitness (SmartScaleConnect): form POST cifrado RC4."""
    nonce = c.generate_nonce(round(time.time() * 1000))  # b64
    sn = c.signed_nonce(nonce)                            # b64

    def sig(data, h=None):
        s = "POST&" + path + "&data=" + data
        if h is not None:
            s += "&rc4_hash__=" + h
        s += "&" + sn
        return base64.b64encode(hashlib.sha1(s.encode()).digest()).decode()

    h = sig(data_str)
    enc_data = c.encrypt_rc4(sn, data_str)
    enc_h = c.encrypt_rc4(sn, h)
    form = {"data": enc_data, "rc4_hash__": enc_h}
    form["signature"] = sig(enc_data, enc_h)
    form["_nonce"] = nonce
    return form, sn


def hlth_call(c, base, data_str):
    form, sn = hlth_request(c, base, PROXY_PATH, data_str)
    cookies = {
        "userId": str(c.userId),
        "serviceToken": str(c._serviceToken),
        "yetAnotherServiceToken": str(c._serviceToken),
    }
    r = requests.post(
        base + PROXY_PATH, data=form, cookies=cookies, timeout=30,
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": c._agent},
    )
    if r.status_code != 200:
        return None, "HTTP %s" % r.status_code
    plain = c.decrypt_rc4(sn, r.text)
    return json.loads(plain), None


def unwrap(resp):
    """Normaliza respuestas {code,result} y proxy {result:{resp:'{...}'}} a la lista de items."""
    if resp is None:
        return None
    cur = resp
    for _ in range(4):
        if isinstance(cur, list):
            return cur
        if not isinstance(cur, dict):
            return None
        if isinstance(cur.get("resp"), str):
            try:
                cur = json.loads(cur["resp"])
                continue
            except ValueError:
                return None
        if "result" in cur:
            cur = cur["result"]
            continue
        if "data" in cur:
            cur = cur["data"]
            continue
        return None
    return cur if isinstance(cur, list) else None


# ---------- consultas ----------
def query_mihome(c, server, did):
    """Via Mi Home (token xiaomiio): mismo endpoint/params que el plugin de la bascula."""
    url = te.XiaomiCloudConnector.get_api_url(server) + PATH_LIST
    params = {"data": json.dumps({"uid": str(c.userId), "deviceId": did, "source": 2})}
    return c.execute_api_call_encrypted(url, params)


def query_hlth(c, server, did):
    """Via Mi Fitness (hlth.io.mi.com, api_proxy) como SmartScaleConnect."""
    base = hlth_base(server)
    if not base:
        return None, "sin host hlth para '%s'" % server
    attempts = [
        {"eco_api": "eco/scale/account/list"},
        {"eco_api": "eco/scale/account/list",
         "params": json.dumps({"uid": str(c.userId), "deviceId": did, "source": 2})},
    ]
    last = None
    for a in attempts:
        resp, err = hlth_call(c, base, json.dumps(a))
        if err:
            last = err
            continue
        return resp, None
    return None, last


def print_users(items, my_id):
    print("   %-4s %-18s %-4s %s" % ("SLOT", "MIID(accountId)", "TIPO", "NOMBRE"))
    for it in sorted(items, key=lambda x: str(x.get("accountCode", ""))):
        mine = " <- tu cuenta" if str(it.get("accountId")) == str(my_id) else ""
        print("   %-4s %-18s %-4s %s%s" % (
            it.get("accountCode"), it.get("accountId"), it.get("type"), it.get("name"), mine))
    print()
    print("   Valores para openScale (SLOT=duid, MIID, TIPO=userType):")
    for it in sorted(items, key=lambda x: str(x.get("accountCode", ""))):
        print("   duid=%s  miid=%s  userType=%s  (%s)" % (
            it.get("accountCode"), it.get("accountId"), it.get("type"), it.get("name")))


def discover_scales(c, server):
    """did/model/nombre de dispositivos que parecen basculas (mismas llamadas que token_extractor)."""
    found, everything = [], []
    homes = c.get_homes(server)
    all_homes = []
    if homes and homes.get("result", {}).get("homelist"):
        for h in homes["result"]["homelist"]:
            all_homes.append((h["id"], c.userId))
    cnt = c.get_dev_cnt(server)
    try:
        for h in cnt["result"]["share"]["share_family"]:
            all_homes.append((h["home_id"], h["home_owner"]))
    except (TypeError, KeyError):
        pass
    for hid, owner in all_homes:
        devs = c.get_devices(server, hid, owner)
        try:
            lst = devs["result"]["device_info"] or []
        except (TypeError, KeyError):
            lst = []
        for d in lst:
            row = (d.get("did"), d.get("model", ""), d.get("name", ""))
            everything.append(row)
            if "scale" in (row[1] + row[2]).lower():
                found.append(row)
    return found, everything


def selftest():
    class _C(te.XiaomiCloudConnector):
        def login(self):
            return True
    c = _C()
    # material sintetico, NO es una credencial real
    c._ssecurity = base64.b64encode(bytes(range(16))).decode()
    c.userId = "1"
    c._serviceToken = "x"
    form, sn = hlth_request(c, "https://hlth.io.mi.com", PROXY_PATH, '{"eco_api":"eco/scale/account/list"}')
    ok = True
    # 1) roundtrip RC4
    back = c.decrypt_rc4(sn, form["data"]).decode()
    ok &= back == '{"eco_api":"eco/scale/account/list"}'
    print("rc4 roundtrip:", back == '{"eco_api":"eco/scale/account/list"}')
    # 2) hash interno = sha1 de la cadena sin rc4_hash__
    h_plain = c.decrypt_rc4(sn, form["rc4_hash__"]).decode()
    exp = base64.b64encode(hashlib.sha1(
        ("POST&" + PROXY_PATH + '&data={"eco_api":"eco/scale/account/list"}&' + sn).encode()).digest()).decode()
    print("rc4_hash__ == sha1(POST&path&data=..&nonce):", h_plain == exp)
    ok &= h_plain == exp
    # 3) firma externa sobre campos cifrados
    exp2 = base64.b64encode(hashlib.sha1(
        ("POST&" + PROXY_PATH + "&data=" + form["data"] + "&rc4_hash__=" + form["rc4_hash__"] + "&" + sn).encode()
    ).digest()).decode()
    print("signature externa:", form["signature"] == exp2)
    ok &= form["signature"] == exp2
    # 4) unwrap de las dos formas de envoltorio
    items = [{"accountCode": 1, "accountId": "9", "type": 1, "name": "t"}]
    w1 = {"code": 0, "result": items}
    w2 = {"code": 0, "result": {"resp": json.dumps({"code": 0, "result": items})}}
    print("unwrap directo:", unwrap(w1) == items, "| unwrap proxy:", unwrap(w2) == items)
    ok &= unwrap(w1) == items and unwrap(w2) == items
    print("SHAPE ejemplo:", json.dumps(shape(w1)))
    print("SELFTEST", "OK" if ok else "FALLO")
    return 0 if ok else 1


def main():
    if MINE.selftest:
        return selftest()
    te.print_banner()
    te.print_if_interactive("Login: p = password, q = QR")
    m = ""
    while m not in ("P", "Q"):
        m = input("p/q: ").upper()
    c = te.PasswordXiaomiCloudConnector() if m == "P" else te.QrCodeXiaomiCloudConnector()
    if not c.login():
        print("No se pudo iniciar sesion.")
        return 1
    print("Login OK.\n")
    servers = [MINE.server] if MINE.server else list(SERVERS)
    got_any = False
    for server in servers:
        if MINE.did:
            scales, _ = [(MINE.did, "?", "?")], None
        else:
            scales, everything = discover_scales(c, server)
            if not scales:
                if everything:
                    print("[%s] sin basculas por nombre/modelo. Dispositivos (did | model | name):" % server)
                    for r in everything:
                        print("   %s | %s | %s" % r)
                    print("   Repite con --did <did de tu bascula> -s %s\n" % server)
                continue
        for did, model, name in scales:
            print("[%s] bascula: %s | %s | %s" % (server, name, model, did))
            for label, fn in (("Mi Home", query_mihome), ("Mi Fitness", query_hlth)):
                try:
                    out = fn(c, server, did)
                    resp, err = (out if isinstance(out, tuple) else (out, None))
                except Exception as e:  # noqa: BLE001 - no filtrar URLs/tokens
                    resp, err = None, type(e).__name__
                if MINE.probe:
                    print("   [%s] forma: %s%s" % (label, json.dumps(shape(resp)) if resp is not None else None,
                                                   (" err=" + err) if err else ""))
                items = unwrap(resp)
                if items:
                    print("   via %s (%d usuarios)\n" % (label, len(items)))
                    print_users(items, c.userId)
                    got_any = True
                    break
                elif not MINE.probe:
                    print("   [%s] sin datos%s" % (label, (" (" + err + ")") if err else ""))
            print()
    if not got_any:
        print("Ningun endpoint devolvio usuarios. Reintenta con --probe y comparte SOLO la forma impresa.")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
