#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Part of the openScale S400 fork (tools/s400_cloud). Needs token_extractor.py next to it; see README.md.
"""scale_history.py - exporta TUS pesajes recientes de una bascula Xiaomi (nube) a un JSON
con una allow-list de campos numericos, para compararlos con openScale.

Reutiliza el login de token_extractor.py (mismo directorio, sin modificarlo). Solo lectura.
Privacidad:
  * Solo registros de TU cuenta (accountId == tu userId). Los demas se cuentan, no se exportan.
  * Salida: fecha (ms), origen, slot (accountCode) y campos numericos de composicion.
    Nunca nombre, MIID, fecha de nacimiento, sexo, cookies ni tokens.
  * El archivo se crea con permisos 600.

Uso:
  python scale_history.py                      # interactivo (p=password / q=QR)
  python scale_history.py -s de --days 7       # fija region y ventana
  python scale_history.py --model yunmai.scales.ms104
  python scale_history.py --probe              # solo claves/tipos de la respuesta, sin valores
  python scale_history.py --selftest           # prueba offline, sin red ni login
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
_ap.add_argument("-s", "--server", default=None, help="de|i2|ru|sg|us (vacio: prueba todas)")
_ap.add_argument("--days", type=int, default=14, help="ventana en dias (default 14)")
_ap.add_argument("--model", default=None, help="modelo de la bascula (default: se detecta)")
_ap.add_argument("--max-pages", type=int, default=10)
_ap.add_argument("-o", "--output", default="s400_xiaomi_history.json")
_ap.add_argument("--probe", action="store_true", help="solo forma de la respuesta, sin valores")
_ap.add_argument("--selftest", action="store_true", help="prueba offline")
OPT = _ap.parse_args()

sys.argv = [sys.argv[0]]  # token_extractor parsea sys.argv al importarse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import token_extractor as te  # noqa: E402

REGIONS = ("de", "i2", "ru", "sg", "us")
PATH = "/eco/common/scale/getUserDataByPage"
DEFAULT_MODEL = "yunmai.scales.ms104"
PAGE = 20

# Allow-list: unicos campos que salen del script. Todos numericos.
FIELDS = (
    "weight", "bmi", "bfp", "bwp", "bmc", "ma", "slm", "bt", "pm", "vfl", "bmr", "sbc", "heartRate",
    "smm", "pp", "swt", "mc", "wc", "fc", "whr", "slp", "bmcp", "bfm", "ffm", "bwm",
    "bodyRes", "bodyRes2", "status",
)


# ---------- cripto / peticion ----------
def _b64sha1(s):
    return base64.b64encode(hashlib.sha1(s.encode()).digest()).decode()


def enc_fields(sign_path, sn, nonce, params, ssecurity=None):
    """Igual que el extractor, pero firmando con la ruta EXPLICITA (el split('com') del
    extractor rompe rutas que contienen 'com', como /eco/common/...)."""
    def sig(p):
        parts = ["POST", sign_path] + ["%s=%s" % (k, v) for k, v in p.items()] + [sn]
        return _b64sha1("&".join(parts))
    p = dict(params)
    p["rc4_hash__"] = sig(p)
    for k, v in list(p.items()):
        p[k] = te.XiaomiCloudConnector.encrypt_rc4(sn, v)
    p["signature"] = sig(p)
    if ssecurity is not None:
        p["ssecurity"] = ssecurity
    p["_nonce"] = nonce
    return p


def post_variants(c, server, body, model):
    """Genera (etiqueta, respuesta_json|None, error|None) para dos formas de peticion."""
    base = te.XiaomiCloudConnector.get_api_url(server)
    url = base + PATH
    cookies = {"userId": str(c.userId), "serviceToken": str(c._serviceToken),
               "yetAnotherServiceToken": str(c._serviceToken), "locale": "en_GB",
               "timezone": "GMT+02:00", "is_daylight": "1", "dst_offset": "3600000",
               "channel": "MI_APP_STORE"}
    data = {"data": json.dumps(body, separators=(",", ":"))}

    def once(label, form_body, extra_headers, with_ss):
        nonce = c.generate_nonce(round(time.time() * 1000))
        sn = c.signed_nonce(nonce)
        fields = enc_fields(PATH, sn, nonce, data, c._ssecurity if with_ss else None)
        headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": c._agent,
                   "MIOT-REQUEST-MODEL": model, "Accept-Encoding": "identity"}
        headers.update(extra_headers)
        try:
            if form_body:
                r = c._session.post(url, headers=headers, cookies=cookies, data=fields, timeout=30)
            else:
                r = c._session.post(url, headers=headers, cookies=cookies, params=fields, timeout=30)
            if r.status_code != 200:
                return label, None, "HTTP %s" % r.status_code
            return label, json.loads(c.decrypt_rc4(sn, r.text)), None
        except Exception as e:  # noqa: BLE001 - no filtrar URLs ni tokens
            return label, None, type(e).__name__

    yield once("form/sin-ssecurity", True, {}, False)
    yield once("query/extractor", False, {"x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
                                           "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4"}, True)


def server_ok(resp):
    return isinstance(resp, dict) and resp.get("code") == 0 and isinstance(resp.get("result"), list)


# ---------- extraccion ----------
def num(v):
    """Numero o None. Acepta int/float/str numerica."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    return None


def flatten(item):
    """Item del servidor -> registro con allow-list, o None si no se puede leer."""
    try:
        d = json.loads(item.get("data") or "{}")
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    layers = [d]
    nested = d.get("bodyResData")
    if isinstance(nested, str):
        try:
            nested = json.loads(nested)
        except ValueError:
            nested = None
    if isinstance(nested, dict):
        layers.append(nested)
    rec = {}
    for k in FIELDS:
        for layer in layers:
            if k in layer and num(layer[k]) is not None:
                rec[k] = num(layer[k])
                break
    user = d.get("user") if isinstance(d.get("user"), dict) else {}
    if num(user.get("height")) is not None:
        rec["height_cm"] = num(user.get("height"))
    if num(user.get("accountCode")) is not None:
        rec["slot"] = int(num(user.get("accountCode")))
    if "weight" not in rec:
        return None
    rec["createTime"] = int(item.get("createTime") or 0)
    rec["fromSource"] = int(item.get("fromSource") or 0)
    return rec


def shape(o):
    if isinstance(o, dict):
        return {k: shape(v) for k, v in o.items()}
    if isinstance(o, list):
        return {"_list_len": len(o), "_item": shape(o[0]) if o else None}
    return type(o).__name__


def collect(fetch, user_id, since_ms, max_pages):
    """fetch(begin_ts_ms) -> lista de items. Pagina como el cliente de referencia."""
    own, others, pages = [], 0, 0
    ts, prev = int(time.time() * 1000), None
    while pages < max_pages:
        items = fetch(ts)
        pages += 1
        for it in items:
            if str(it.get("accountId")) != str(user_id):
                others += 1
                continue
            rec = flatten(it)
            if rec and rec["createTime"] >= since_ms:
                own.append(rec)
        if len(items) < PAGE:
            break
        ts = int(items[PAGE - 1].get("createTime") or 0)
        if ts <= 0 or ts == prev or ts < since_ms:
            break
        prev = ts
    uniq = {(r["createTime"], r["fromSource"]): r for r in own}
    return sorted(uniq.values(), key=lambda r: r["createTime"]), others, pages


def discover_models(c, server):
    models = set()
    homes = c.get_homes(server)
    pairs = []
    try:
        pairs += [(h["id"], c.userId) for h in homes["result"]["homelist"]]
    except (TypeError, KeyError):
        pass
    try:
        pairs += [(h["home_id"], h["home_owner"]) for h in c.get_dev_cnt(server)["result"]["share"]["share_family"]]
    except (TypeError, KeyError):
        pass
    for hid, owner in pairs:
        try:
            for d in c.get_devices(server, hid, owner)["result"]["device_info"] or []:
                m = d.get("model", "")
                if "scale" in m.lower():
                    models.add(m)
        except (TypeError, KeyError):
            continue
    return sorted(models)


# ---------- selftest ----------
def selftest():
    ok = True

    def chk(name, cond):
        nonlocal ok
        ok &= bool(cond)
        print("%-52s %s" % (name, "OK" if cond else "FALLO"))

    # 1) firma con ruta explicita, y que el split('com') del extractor SI se rompe
    chk("la ruta contiene 'com' (motivo del fix)", len("https://x.api.io.mi.com/app".split("com")) >= 2
        and "/app/eco/" == ("https://de.api.io.mi.com/app" + PATH).split("com")[1])
    ss = base64.b64encode(bytes(range(16))).decode()
    nonce = base64.b64encode(bytes(range(12))).decode()
    sn = base64.b64encode(hashlib.sha256(base64.b64decode(ss) + base64.b64decode(nonce)).digest()).decode()
    data = {"data": '{"a":1}'}
    f = enc_fields(PATH, sn, nonce, data)
    chk("data cifrado/descifrado (RC4) ida y vuelta",
        te.XiaomiCloudConnector.decrypt_rc4(sn, f["data"]) == b'{"a":1}')
    h = te.XiaomiCloudConnector.decrypt_rc4(sn, f["rc4_hash__"]).decode()
    chk("rc4_hash__ = sha1(POST&ruta&data=..&sn)", h == _b64sha1("POST&%s&data={\"a\":1}&%s" % (PATH, sn)))
    chk("signature externa sobre campos cifrados",
        f["signature"] == _b64sha1("POST&%s&data=%s&rc4_hash__=%s&%s" % (PATH, f["data"], f["rc4_hash__"], sn)))
    chk("sin ssecurity por defecto / con ssecurity si se pide",
        "ssecurity" not in f and "ssecurity" in enc_fields(PATH, sn, nonce, data, ss))

    # 2) flatten: allow-list, anidado, filtrado de PII
    pii = {"name": "N", "birth": 1, "sex": "1", "miid": "1", "accountId": "1", "height": "180", "accountCode": 3}
    raw = {"createTime": 1700000000000, "fromSource": 3, "accountId": 7, "data": json.dumps(
        {"weight": "80.5", "bmi": "24.1", "heartRate": 70, "user": pii, "miid": "123",
         "bodyResData": json.dumps({"bfp": "20.5", "slm": "60.1", "smm": 30.2, "name": "X"})})}
    r = flatten(raw)
    chk("flatten une capa anidada bodyResData", r and r.get("bfp") == 20.5 and r.get("slm") == 60.1)
    chk("flatten conserva slot y estatura", r and r.get("slot") == 3 and r.get("height_cm") == 180.0)
    blob = json.dumps(r)
    chk("sin PII en la salida (name/birth/sex/miid)", not any(k in blob for k in ("name", "birth", "sex", "miid")))
    chk("sin peso -> descartado", flatten({"data": "{}", "createTime": 1}) is None)

    # 3) paginacion + filtro de cuenta
    now = int(time.time() * 1000)

    def mk(i, acc):
        return {"createTime": now - i * 1000, "fromSource": 3, "accountId": acc,
                "data": json.dumps({"weight": str(70 + i % 3)})}
    pages = {0: [mk(i, 7 if i % 2 == 0 else 9) for i in range(1, 21)],
             1: [mk(i, 7) for i in range(21, 30)]}
    calls = []

    def fetch(ts):
        calls.append(ts)
        return pages[len(calls) - 1]
    recs, others, n = collect(fetch, 7, now - 10 ** 9, 5)
    chk("pagina hasta pagina corta (2 llamadas)", n == 2 and len(calls) == 2)
    chk("solo cuenta propia; ajenas contadas, no exportadas", others == 10 and len(recs) == 10 + 9)
    chk("orden cronologico y sin duplicados",
        [r["createTime"] for r in recs] == sorted({r["createTime"] for r in recs}))
    chk("shape() no expone valores", "80" not in json.dumps(shape(raw)))
    print("SELFTEST", "OK" if ok else "FALLO")
    return 0 if ok else 1


# ---------- main ----------
def main():
    if OPT.selftest:
        return selftest()
    te.print_banner()
    print("Login: p = password, q = QR")
    m = ""
    while m not in ("P", "Q"):
        m = input("p/q: ").upper()
    c = te.PasswordXiaomiCloudConnector() if m == "P" else te.QrCodeXiaomiCloudConnector()
    if not c.login():
        print("No se pudo iniciar sesion.")
        return 1
    print("Login OK.\n")
    since_ms = int((time.time() - OPT.days * 86400) * 1000)
    regions = [OPT.server] if OPT.server else list(REGIONS)
    if any(r not in REGIONS for r in regions):
        print("Region no soportada por este endpoint. Validas:", ", ".join(REGIONS))
        return 1
    model = OPT.model
    for server in regions:
        models = [model] if model else (discover_models(c, server) or [DEFAULT_MODEL])
        for mdl in models:
            print("[%s] modelo %s" % (server, mdl))

            def fetch(ts, _s=server, _m=mdl):
                body = {"endTime": 1, "beginTime": ts, "model": _m, "uid": str(c.userId),
                        "did": 0, "accountId": 0}
                last = None
                for label, resp, err in post_variants(c, _s, body, _m):
                    if OPT.probe:
                        print("   [%s] %s%s" % (label, json.dumps(shape(resp)) if resp is not None else None,
                                                (" err=" + err) if err else ""))
                    if server_ok(resp):
                        return resp["result"]
                    last = (label, err, resp.get("code") if isinstance(resp, dict) else None,
                            resp.get("message") if isinstance(resp, dict) else None)
                fetch.last = last
                return []
            fetch.last = None
            recs, others, pages = collect(fetch, c.userId, since_ms, OPT.max_pages)
            if not recs:
                print("   sin registros propios (ajenos vistos: %d, paginas: %d)%s\n" % (
                    others, pages, (" ultimo error: %s" % (fetch.last,)) if fetch.last else ""))
                continue
            fd = os.open(OPT.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump({"region": server, "model": mdl, "count": len(recs), "records": recs}, fh)
            os.chmod(OPT.output, 0o600)
            src = {}
            for r in recs:
                src[r["fromSource"]] = src.get(r["fromSource"], 0) + 1
            print("   registros propios: %d | ajenos excluidos: %d | paginas: %d" % (len(recs), others, pages))
            print("   fromSource: %s" % json.dumps(src))
            print("   campos presentes: %s" % ", ".join(sorted({k for r in recs for k in r} - {"createTime"})))
            print("   escrito: %s (permisos 600)\n" % os.path.abspath(OPT.output))
            return 0
    print("Ninguna region devolvio registros. Reintenta con --probe y comparte SOLO la forma impresa.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
