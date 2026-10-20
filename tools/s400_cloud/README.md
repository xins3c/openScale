# S400 cloud helpers

Two read-only helpers for onboarding a Xiaomi S400 into openScale and for comparing
its weigh-ins with what the Xiaomi cloud holds. They reuse the login of the stock
**Xiaomi Cloud Tokens Extractor** (`token_extractor.py`), which is not vendored here.

You run them with your own Xiaomi credentials. Nothing is stored or sent anywhere but
Xiaomi's servers, and neither script writes anything back to the cloud or to the scale.

## Setup

1. Get `token_extractor.py` from the upstream project (Xiaomi Cloud Tokens Extractor)
   and **read it before running it**. The helpers were tested against a copy with
   SHA-256 `e4eb8220df0f68c945c21cde5dbc5a0a276e7a035857b568d9423788ef192a30`
   (`requests`, `pycryptodome`, `colorama`, `Pillow`). A different version may work,
   but then re-run `--selftest` and review the diff.
2. Put `scale_users.py` and `scale_history.py` in the same directory.
3. Use a throwaway virtualenv; do not install into a system or work environment.

## `scale_users.py` - who is which slot

```sh
python scale_users.py            # interactive login (password or QR)
python scale_users.py -s de      # fix the server
python scale_users.py --probe    # print only the response shape
```

Lists the scale's cloud accounts (`eco/scale/account/list`): slot (`accountCode`),
MIID (`accountId`), `userType` and display name, and prints `duid= miid= userType=`
lines to type into openScale. The scale stores slot numbers only; names exist
only in the cloud. Birth date, height and sex are never printed.
Confirmed working against a real account.

## `scale_history.py` - compare weigh-ins with Xiaomi

```sh
python scale_history.py -s de --days 7    # writes s400_xiaomi_history.json (mode 600)
python scale_history.py --probe           # shape only, no values
python scale_history.py --selftest        # offline, no network, no login
```

Exports the owner's own recent weigh-ins from `/eco/common/scale/getUserDataByPage`
using a fixed allow-list of numeric fields (weight, body fat, water, bone, lean mass,
muscle, BMR, impedances...). Other accounts' records are counted, not exported.
The file holds health data: keep it out of version control (`.gitignore` covers it),
and delete it after use.

**Status:** `--selftest` passes (cipher, signatures, flattening, privacy filter,
paging). The history endpoint and request format come from the open-source
SmartScaleConnect client and have **not** been confirmed against a live account yet.
It signs with the explicit path because the extractor's `url.split("com")[1]`
mis-handles paths containing `com` (`/eco/common/...`).

## Privacy rules these scripts follow

- No credentials, cookies, tokens or service tokens are printed or written.
- Output is an allow-list of numeric fields plus timestamp and slot; never name, MIID,
  birth date or sex.
- `--probe` prints keys and types only.
