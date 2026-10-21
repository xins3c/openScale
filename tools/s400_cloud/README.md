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

### Which MIID goes into openScale

The MIID that `scale_users.py` prints for a row is the cloud `accountId` of that row. It is
**not necessarily what the scale is sent**. Xiaomi Home has two ways to add a person, and only
one of them has been checked on the wire:

| How the person was added | MIID to enter in openScale | Status |
|---|---|---|
| **Member added from the scale's own screen** in Xiaomi Home (no Xiaomi account of their own) | The **account owner's** MIID, with that member's own slot (`duid`) and `userType` | Verified: a decrypted Bluetooth capture of Xiaomi Home shows `switchUser` carrying the owner's MIID with the member's slot and type, and openScale then stored a complete weigh-in for that member using exactly this combination |
| **Family-account member who has their own Xiaomi account** (invited from the Home dashboard) | Probably their own MIID | **Not verified**: never captured. Treat as unknown until someone tests it |

Observed values on the verified setup: owner = slot 1 / type 1, first member = slot 2 / type 2.
The user-type hint in the app used to say "0 = family member"; no real traffic supports a `0`,
and `duid` 0 is what the scale sends when it did not attribute a weigh-in, so openScale now
rejects it. Slots and types come from your own `scale_users.py` run; do not copy the numbers above.

### Several people, one scale

Each person uses their own openScale instance (or their own openScale user) holding **one**
identity: MIID, slot, user type and the mapped openScale user. TOKEN and BLE KEY are the scale
owner's and are shared; they give access to the whole scale, not only to one profile, so hand
them over deliberately.

What was observed with two people on the same scale:

- With the right identity selected and a **fresh connection**, both the owner and the member got
  a complete result (composition, BMI, pulse).
- openScale reads the identity **once per connection**. Editing the identity fields or switching
  the openScale user while the scale is still connected sends no new `switchUser`; the scale
  stays on the previous slot, and a different person stepping on gets `status 2` (weight only,
  nothing saved). **Disconnect the scale and reconnect before the next person weighs in.**
- Not known: whether the scale would accept a second `switchUser` inside the same connection, so
  the reconnect is the safe rule, not a proven requirement.
- The earlier "secondary profiles never work" results came from tests where the owner and the
  member both stepped on the scale. Always note **who stood on it** before reading a `status 2`
  as a bug.
- Evidence so far is consistent with the scale checking the measured weight against the base
  weight stored for the active slot, but that is an inference: it was not isolated from other
  explanations, and the tolerance is unknown (a difference under ~0.5 kg was attributed, over
  ~6 kg was not). The fork never updates that stored weight; Xiaomi Home does after each weigh-in.
- Two phones connecting to the scale at the same time have not been tested.

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

**Status:** confirmed against a live account (S400 EU, `yunmai.scales.ms104`, served
through the Xiaomi Home app's `getUserDataByPage`, 50 records, `fromSource` 2). The
offline `--selftest` also passes (cipher, signatures, flattening, privacy filter, paging).
Request format taken from the open-source SmartScaleConnect client. It signs with the
explicit path because the extractor's `url.split("com")[1]` mis-handles paths containing
`com` (`/eco/common/...`).

Field notes from the live export: Xiaomi's "muscle %" is `slp`, not `smm`/weight; and the
cloud can hold several records with the same impedance pair for one physical weigh-in, so
equal impedance alone does not prove two records are the same measurement.

## Privacy rules these scripts follow

- No credentials, cookies, tokens or service tokens are printed or written.
- Output is an allow-list of numeric fields plus timestamp and slot; never name, MIID,
  birth date or sex.
- `--probe` prints keys and types only.
