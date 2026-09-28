# FOR-100 — Everything Left Open

**Category:** Forensics / Wave 1  
**Points:** 100  
**Artifact:** `left-open-profile-team-485.zip`  
**SHA-256:** `ff90987d75354c09b7e46b2377135075f4911e26d814c8fb0dbddb528f2dd09b`

**Result:** Solved — 140 solves at the time of analysis

**Flag:**

```text
POCTF{109.485.X25EU43TGQXOMZQT.QZ5C7KS7JOLMQF3YMLJAY6ABZZ}
```

---

## 1. Overview

This challenge is a good example of why browser forensics is often about recovering **state**, not just looking through browsing history.

We were given a small Firefox profile extracted from an unlocked workstation. The last active page was an SPR provenance form, and the task was to find what the user was about to submit.

The key artifact turned out to be `sessionstore-backups/recovery.jsonlz4`.

Firefox had preserved the unfinished form inside its session-recovery data. Once the `mozLz40` container was decoded and the embedded LZ4 block decompressed, the pending `formdata.id.artifact-flag` value was recovered directly.

No password cracking, network exploitation, or brute force was necessary. The challenge was mainly about browser-session restoration and cross-correlating the evidence.

---

# 2. Authorization and Scope

The analysis was limited to the supplied challenge artifact:

`~/CTF/files/left-open-profile-team-485.zip`

It contained the Firefox profile:

`k-vance-profile/`

The only external hostname noticed during passive analysis was `admin.pointeroverflowctf.com`, which appeared through a suspicious Firefox `rev_host` value. It did not resolve, so it was logged as an artifact anomaly and not pursued.

---

# 3. Initial Reconnaissance

I began with a basic archive inventory instead of opening files at random:

```bash
python3 -c "import zipfile; z=zipfile.ZipFile('left-open-profile-team-485.zip'); print('\\n'.join(f'{i.filename} {i.file_size}' for i in z.infolist()))"
```

The archive contained:

```text
k-vance-profile/places.sqlite                         12288
k-vance-profile/logins.json                            1017
k-vance-profile/formhistory.sqlite                     8192
k-vance-profile/sessionstore-backups/recovery.jsonlz4  584
k-vance-profile/prefs.js                               212
README.txt                                              407
```

This immediately looked like a deliberately minimal Firefox profile. That narrowed the investigation toward browser persistence mechanisms: history, bookmarks, typed form data, saved credentials, preferences, and session restoration.

### Zip metadata

The ZIP entries all reported:

```text
create_system = 3 (Unix)
timestamp     = 2026-06-29 12:00:00
extra fields  = none
comment       = none
```

That is consistent with synthetic challenge packaging and the supplied chain-of-custody date.

---

# 4. Case Notes

The included `README.txt` provided the investigation context:

```text
DOCKET  MARCHETTI / 2026-14
SUBJECT E. Marchetti - disappearance investigation
ANALYST K. Vance (retained by R. Marchetti)
----------------------------------------
Attached: Firefox profile pulled from Elena's office
workstation at Hollis University, found unlocked with
an SPR provenance page in the last active tab.
Session appears to have been interrupted mid-review.

Find what she was about to submit.
```

The briefing also referenced a hotel laptop, while the artifact clearly came from an office workstation. I kept that discrepancy as evidence rather than treating it as a typo; it may be relevant to later waves.

---

# 5. Forensic Enumeration Methodology

I used a browser-forensics workflow that prioritized volatile or session-related state and then cross-correlated the results:

1. `prefs.js` — startup and crash/session behaviour
2. `places.sqlite` — browsing history and bookmarks
3. `formhistory.sqlite` — previously entered values
4. `logins.json` — saved credentials
5. `sessionstore-backups/recovery.jsonlz4` — active tabs and unsubmitted form state
6. Raw carving and integrity checks

The important point was not to assume where the flag lived. Each store was checked against the others and timestamps were used to build a consistent timeline.

---

# 6. prefs.js — Session Recovery Was Enabled

The relevant Firefox settings were:

```javascript
user_pref("general.useragent.override", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/119.0");
user_pref("browser.startup.page", 3);
user_pref("browser.sessionstore.resume_from_crash", true);
```

The most important setting was:

`browser.sessionstore.resume_from_crash = true`

Together with `browser.startup.page = 3`, this supported the challenge description of an interrupted browser session.

That made `recovery.jsonlz4` a high-priority artifact.

---

# 7. places.sqlite — Rebuilding the Browser Trail

The SQLite database was intentionally small.

Present tables:

```text
moz_places
moz_bookmarks
```

There was no `moz_historyvisits` table, so this was clearly not a complete native Firefox history database.

Still, `moz_places` gave us a useful sequence of pages:

| ID | URL / Title | Visits |
|---:|---|---:|
| 7 | Firefox Profile Manager | 7 |
| 6 | Wikipedia — LZ4 | 6 |
| 5 | Wikipedia — Society for Psychical Research | 5 |
| 4 | Google Scholar — marcus yee dissertation liminal | 4 |
| 3 | Hollis LSSF Papers | 3 |
| 2 | SPR LSSF Session Records | 2 |
| 1 | SPR Catalogue | 1 |
| 99 | LSSF Apparatus — Provenance & Loan History | 1 |

The browsing path formed a clear progression:

```text
Profile Manager
     ↓
LZ4 research
     ↓
SPR
     ↓
Marcus Yee research
     ↓
LSSF Papers
     ↓
LSSF Session Records
     ↓
SPR Catalogue
     ↓
LSSF Apparatus / Provenance
```

The final provenance page was therefore the obvious place to investigate.

### The id=99 anomaly

The final record had a suspicious `rev_host`:

```text
moc.ftcwolfrevoretniop.nimda.
```

Reversing it gives:

`admin.pointeroverflowctf.com`

But the actual URL belonged to:

`catalog.spr.org.uk`

There were additional anomalies:

```text
id = 99
frecency = 2000
```

while the ordinary records used IDs 1–7 and frecency 100.

The database itself still passed integrity checking:

```text
PRAGMA integrity_check = ok
freelist = 0
page_size = 4096
page_count = 3
```

A raw carve did not reveal a second `POCTF` value.

---

# 8. Bookmarks

The bookmark table contained:

`flag draft (do not lose)`

with timestamp:

`2026-06-30T16:56:29Z`

The bookmark pointed to the Hollis LSSF Papers page rather than storing the flag itself.

It was still a useful clue that some important value existed elsewhere in the profile.

---

# 9. formhistory.sqlite — Useful Context, No Flag

Firefox form history contained only:

```text
search -> eighth session lssf redacted
email  -> e.marchetti@hollis.edu
search -> halberd office hours wednesday
```

No flag was stored here.

These values were more useful for reconstructing the research path than for direct extraction.

---

# 10. logins.json — Credential and Timeline Correlation

The saved credentials were synthetic and stored as plain Base64 rather than NSS-encrypted secrets.

Examples:

```text
ZS5tYXJjaGV0dGlAaG9sbGlzLmVkdQ==
    -> e.marchetti@hollis.edu

TW5EYXlXM2RuZXNkQHk3
    -> MnDayW3dnesd@y7

YW5vbi1hbmFseXN0
    -> anon-analyst

aHVudGVyMg==
    -> hunter2
```

The Hollis credential's `timeLastUsed` matched the final provenance activity. That was valuable for timeline validation.

I treated `hunter2` as a synthetic/test-style credential and did not assume it enabled escalation.

---

# 11. The Breakthrough — recovery.jsonlz4

The critical file was:

`k-vance-profile/sessionstore-backups/recovery.jsonlz4`

It was only 584 bytes long.

Its first eight bytes were:

```text
6d 6f 7a 4c 7a 34 30 00
```

which is the Firefox magic:

`mozLz40\0`

This was the turning point.

Instead of searching for strings, I switched to decoding the Firefox session format.

---

# 12. Exploitation — Decoding the mozLz4 Container

The important format detail is:

```text
8-byte magic
4-byte little-endian uncompressed size
LZ4 block
```

Therefore, the actual LZ4 stream starts at offset **12**.

The correct decoder was:

```python
import lz4.block
import json

raw = open(
    "k-vance-profile/sessionstore-backups/recovery.jsonlz4",
    "rb"
).read()

size = int.from_bytes(raw[8:12], "little")

dec = lz4.block.decompress(
    raw[12:],
    uncompressed_size=size
)

j = json.loads(dec)
```

A common mistake is to start decompression at `raw[8:]`. That leaves the four-byte size field inside the LZ4 input and causes decompression to fail.

The correct offset is:

`raw[12:]`

---

# 13. Recovered Session Data

Once decompressed, the JSON exposed the active tab and its preserved form state.

The important fields were:

```json
{
  "url": "https://catalog.spr.org.uk/apparatus/provenance/lssf",
  "title": "LSSF Apparatus — Provenance & Loan History",
  "formdata": {
    "id": {
      "workstation": "hollis-office-desktop-elena",
      "analyst-name": "K. Vance",
      "artifact-flag": "POCTF{109.485.X25EU43TGQXOMZQT.QZ5C7KS7JOLMQF3YMLJAY6ABZZ}",
      "case-notes": "Subject: E. Marchetti disappearance. Chain of custody initiated 2026-06-29. See docket MARCHETTI/2026-14."
    }
  }
}
```

The flag was sitting directly inside:

`formdata.id.artifact-flag`

This was the intended artifact.

---

# 14. Why the "Exploit" Works

There is no Firefox memory-corruption bug to exploit here.

The real technique is recognizing how Firefox preserves browser state after an interrupted session.

The relevant conditions were:

```text
browser.sessionstore.resume_from_crash = true
browser.startup.page = 3
recovery.jsonlz4 exists
```

The flow is:

```text
User types data
      ↓
Form state exists in the browser
      ↓
Session is interrupted
      ↓
Firefox snapshots recovery state
      ↓
Formdata survives in sessionstore
      ↓
Forensic recovery
```

This is why the challenge title, **Everything Left Open**, is such a strong hint.

---

# 15. Post-Exploitation Verification

Finding a flag-shaped string is not enough in a forensic case, so I verified it through the artifact chain.

The recovery file was:

- read directly from the supplied ZIP
- hash-verified
- decoded using the `mozLz40` format
- decompressed with LZ4
- parsed as JSON
- queried programmatically for `artifact-flag`

The timestamp also lined up with other browser artifacts:

`2026-07-01T16:56:29Z`

That matched the final provenance visit and the relevant Hollis login activity.

The flag also contained:

`109.485`

which is consistent with the team-specific challenge artifact.

A raw search through the SQLite databases did not reveal another `POCTF` value, supporting the conclusion that the recovered flag was unique.

---

# 16. Timeline

All times are UTC.

| Timestamp | Event |
|---|---|
| 2026-06-01 16:56:29 | `e.marchetti@hollis.edu` first used |
| 2026-06-28 16:56:29 | Hollis login created |
| 2026-06-29 12:00:00 | ZIP packaging / chain-of-custody timestamp |
| 2026-06-30 16:56:29 | `flag draft (do not lose)` bookmark created |
| 2026-06-30 16:56:29 | Password / Pastebin activity recorded |
| 2026-07-01 09:56–15:56 | Research progression through profile manager, LZ4, SPR, dissertation, Hollis papers, session records, and catalogue |
| 2026-07-01 16:56:29 | Final provenance-page visit, Hollis login use, and sessionstore snapshot |

This timeline is internally coherent with an interrupted review occurring at the end of the sequence.

---

# 17. Details to Preserve for Follow-on Waves

Several anomalies were not necessary for Wave 1 but are worth preserving:

### Workstation

`hollis-office-desktop-elena`

### Analyst

`K. Vance`

### Subject / docket

`E. Marchetti`  
`MARCHETTI/2026-14`

### Chain of custody

`2026-06-29`

### Location discrepancy

`README -> hotel laptop`  
`artifact -> Hollis office workstation`

### Firefox metadata anomaly

```text
rev_host -> admin.pointeroverflowctf.com
id       -> 99
frecency -> 2000
```

### Search trail

```text
eighth session lssf redacted
halberd office hours wednesday
marcus yee dissertation liminal
```

### Bookmark clue

`flag draft (do not lose)`

I would preserve these rather than normalize or delete them. They may be intentional leads for subsequent waves.

---

# 18. Lessons Learned

### 1. Session artifacts can beat browser history

History tells you where the user went. Session recovery can reveal what was actually left open in the browser.

### 2. Recognize Firefox compressed formats

For `recovery.jsonlz4`, the correct sequence is:

```text
mozLz40
   ↓
read 4-byte LE size
   ↓
skip 12-byte header
   ↓
LZ4 decompression
   ↓
JSON parsing
```

Using `strings` alone can reveal fragments, but it loses the structure that makes the evidence useful.

### 3. Correlate timestamps

The recovered flag became much stronger evidence once it matched the provenance-page visit and login timeline.

### 4. Preserve anomalies

The `rev_host` mismatch and the hotel-vs-office discrepancy were not required for the flag, but forensic cases often hide the next lead inside these inconsistencies.

---

# 19. Reproduction

Verify the archive:

```bash
sha256sum left-open-profile-team-485.zip
```

Expected:

```text
ff90987d75354c09b7e46b2377135075f4911e26d814c8fb0dbddb528f2dd09b
```

Install LZ4:

```bash
pip install --break-system-packages -q lz4
```

Extract the flag directly:

```bash
python3 -c "import lz4.block,json; d=open('k-vance-profile/sessionstore-backups/recovery.jsonlz4','rb').read(); s=int.from_bytes(d[8:12],'little'); print(json.loads(lz4.block.decompress(d[12:],uncompressed_size=s))['windows'][0]['tabs'][0]['entries'][0]['formdata']['id']['artifact-flag'])"
```

Expected output:

```text
POCTF{109.485.X25EU43TGQXOMZQT.QZ5C7KS7JOLMQF3YMLJAY6ABZZ}
```

---

# 20. Final Flag

```text
POCTF{109.485.X25EU43TGQXOMZQT.QZ5C7KS7JOLMQF3YMLJAY6ABZZ}
```

## Takeaway

The challenge was not about attacking Firefox. It was about understanding what Firefox leaves behind.

**Recon** established the profile and its structure.  
**Enumeration** rebuilt the browser trail.  
**Format analysis** exposed the session-recovery data.  
**Verification** tied the recovered value back to the timeline.

The final flag was not submitted successfully by the user — it was simply still present in the browser's preserved form state.
