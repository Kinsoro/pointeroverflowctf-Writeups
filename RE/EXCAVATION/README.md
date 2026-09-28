# EXCAVATION — RE-100/WAVE-01 Writeup

**Game:** *Sepulchure of the Undying* — fictional dark-fantasy RPG  
**Category:** Reverse Engineering  
**Challenge:** RE-100 / WAVE-01  
**Artifacts:** `sample1.sav`, `sample2.sav`, `sample3.sav`, `team_485.sav`

**Objective:** Recover the 16-character token and submit it either directly or wrapped as `POCTF{...}`.

**Flag:**

```text
IE6HKEDLJZZWNSKB

POCTF{IE6HKEDLJZZWNSKB}
```

---

## 1. Reconnaissance

I started by treating the save files as unknown binary artifacts rather than assuming they used a standard game-save format.

The first pass was basic file inventory, hashing, size checking, and a quick hex inspection:

```bash
ls -l
sha256sum *.sav
wc -c *.sav
xxd sample1.sav | head
```

The resulting files were:

| File | Size | SHA-256 |
|---|---:|---|
| `sample1.sav` | 466 | `6ed4defc4ca96b9f28086375ca2f0d690a6af708c51e78746a67dc49ce9ac1a2` |
| `sample2.sav` | 857 | `d2660f5a5d0577daa30c0e57264434b8be0267dcd496bd6afbe9fc00f6c8582c` |
| `sample3.sav` | 1144 | `1bd1418716899948646b314d48c01dd16ab5d4720501ef582a7392a61378e1b0` |
| `team_485.sav` | 1380 | `3563b3d419fa695fac77e936f44f8e1e6044d7952ec0f88dfae2f1e297386afd` |

The hashes matched the challenge description, so I knew I was working with the intended samples.

### Binary header

All four files shared the same 12-byte header:

```text
9e e1 c7 21 | 02 00 02 00 | <u32LE total_len>
```

That gave us three immediate fields:

```python
magic = data[0:4]                            # 9ee1c721
version = data[4:8]                          # 02000200
total = int.from_bytes(data[8:12], "little") # file size
payload = data[12:]
```

The `total` field matched the actual file size in every sample:

```text
sample1   -> 454-byte payload
sample2   -> 845-byte payload
sample3   -> 1132-byte payload
team_485  -> 1368-byte payload
```

There was no obvious IV or other cipher metadata in the header.

The payload itself had fairly high entropy and did not resemble a normal compressed save or plain serialized structure.

At this point, the interesting part was clearly inside the payload.

---

## 2. Enumeration

### 2.1 Byte-level statistics

I checked the byte distribution to determine whether the payload was compressed, encrypted, or simply obfuscated.

```python
from collections import Counter

counter = Counter(payload)
print(counter.most_common())
print(len(set(payload)))
```

Unique-byte counts were:

```text
sample1    157
sample2    178
sample3    195
team_485   193
```

The distributions were not uniform.

Some useful indicators:

```text
IOC:
sample1    0.0082
sample2    0.0104
sample3    0.0084
team_485   0.0090
```

For comparison, uniformly random data would be around `0.0039`.

I also checked low-valued 16-bit integers and null bytes:

```text
u16 < 256:
0.00%, 1.66%, 0.18%, 0.00%

zeros:
0.22%, 0.83%, 0.09%, 0.00%
```

So the payload was not random-looking enough to confidently call it proper encryption, but it was definitely not readable text either.

That suggested some form of lightweight byte-wise transformation rather than compression.

---

## 3. Repeated-Ciphertext Analysis

The next high-signal test was searching for repeated byte sequences.

I looked for aligned and unaligned repeats of at least 8 bytes.

The important matches were:

```text
sample1:     no significant repeats

sample2:     46-byte repeat at offsets 445 and 493
             distance = 48

sample3:     46-byte repeat at offsets 602 and 650
             distance = 48
             9-byte repeat at 227 and 531
             distance = 304
             8-byte repeat at 357 and 381
             distance = 24

team_485:    8-byte repeat at 149 and 205
             distance = 56
```

The `sample2` repeat was particularly useful.

The two 48-byte records looked like:

```text
A @ 445:
... ff a3 74 cc b1 ... ce00 ce8f c454 dcec bd69 a0 ff ...

B @ 493:
... ff a3 74 cc b1 ... ce00 ce8f c454 dcec bd68 a3 fd ...
```

The first **46 bytes were identical**, with only the final two bytes differing.

Even more importantly:

```text
445 + 48 = 493
602 + 48 = 650
```

The repeated regions also preserved the same alignment:

```text
445 % 48 == 493 % 48
445 % 16 == 493 % 16
```

That strongly suggested that identical plaintext structures were being transformed in a way that preserved ciphertext bytes over repeated records.

---

## 4. Cipher-Type Elimination

Before trying to recover a key, I wanted to establish what the transform could *not* be.

### CBC / CFB

CBC- or CFB-style chaining should propagate differences from previous blocks.

Here, the preceding bytes were different:

```text
dfdf5ad9ecbd66a1
8fc454dcecbd69a0
```

Yet the following 46 bytes were identical.

That is inconsistent with chained block modes.

**Conclusion:** CBC/CFB were effectively ruled out.

### ECB

ECB would preserve repeated plaintext blocks, but the repeated sequences did not start on clean 16-byte boundaries:

```text
13 % 16
10 % 16
```

The identical data also included surrounding bytes that would normally belong to neighboring ECB blocks.

Unless the cipher had a block size of one byte, ECB did not fit the evidence.

**Conclusion:** Standard ECB was ruled out.

### Position-dependent stream transformations

An LCG stream, RC4-style keystream, CTR mode, or any transformation where the keystream changes with position would normally produce different ciphertext when the same plaintext appears 48 bytes later.

Instead, we observed 46-byte identical ciphertext regions.

The chance of getting a 46-byte random match is approximately:

```text
256^-46
```

which is effectively negligible.

**Conclusion:** the transformation was very unlikely to be position-dependent.

---

## 5. Exploitation Hypothesis: Repeating XOR

The remaining model was a simple byte-wise repeating-key transformation:

```text
C[i] = P[i] XOR K[i mod L]
```

or potentially the same structure using another reversible byte-wise operation such as addition.

The repeat distances gave another useful constraint.

Observed distances:

```text
48
48
304
24
56
```

Their greatest common divisor is:

```text
gcd(48, 48, 304, 24, 56) = 8
```

Therefore the repeating key length had to divide 8:

```text
L ∈ {1, 2, 4, 8}
```

This reduced the problem dramatically.

I also compared ciphertexts across files. The data did not indicate a global shared keystream, so the most likely model was:

```text
same algorithm
different key per save file
```

---

## 6. Testing the Key Length

I tested the candidate key lengths by splitting the ciphertext into residue classes and looking at which key byte produced the strongest plaintext statistics.

The results were immediately interesting.

### `L = 1`

Very weak.

```text
zeros      ≈ 2.4%
printable  ≈ 30–65%
```

### `L = 8`

A much stronger signal appeared:

```text
zeros      ≈ 12%
u16-small  ≈ 12%
printable  ≈ 51–67%
```

### `L = 48`

This produced even higher local scores, but that was simply overfitting.

The strongest meaningful candidate was clearly:

```text
L = 8
```

I then tested sample3 using a preliminary zero-key-derived guess:

```text
a32903e8dcf7b07d
```

The result was not perfectly readable, but it was clearly English-like:

```text
Poi+1s at y*0r own 6,gnatur
welve ($rks. O+)y ninee...
```

That was enough to confirm the direction.

The errors were consistent with a small number of incorrect key bytes.

For example:

```text
+ vs n
2b ^ 6e = 45

1 vs t
31 ^ 74 = 45

* vs o
2a ^ 6f = 45
```

The repeated `0x45` difference was a strong indication that the transform really was XOR and that only specific key residues needed correction.

---

## 7. Key Recovery

I built a simple frequency-based scoring function for English plaintext.

The idea was straightforward:

- space should be very common
- lowercase English letters should score highly
- uppercase letters should be possible but less common
- punctuation and digits should be allowed
- control and non-printable bytes should score very poorly

The scoring table looked roughly like this:

```text
space       = 18.0
e           = 9.5
t           = 7.0
a           = 6.5
...
z           = 0.1

uppercase   = lowercase * 0.08
punctuation = 1.0
digit       = 0.5
0x00        = 0.3
other-print = 0.05
other       = 0.01
```

For every residue position `r`, I tested all 256 possible key bytes:

```python
for r in range(L):
    chunk = data[r::L]

    best = max(
        range(256),
        key=lambda k: score(bytes(b ^ k for b in chunk))
    )
```

Since `L = 8`, this is only:

```text
8 × 256 = 2048
```

key candidates per file.

No brute-forcing of large seeds, passwords, or wordlists was required.

### Recovered keys

The final keys were:

```text
sample1    9fd3468039032887
sample2    aec2ad61a3ffac3b
sample3    c60923c8fcd79018
team_485   3950dfa7af8cb8ce
```

The same key recovered independently from the plaintext structure, which gave a good sanity check that the model was correct.

---

## 8. Decryption

The payload can now be decrypted with a simple repeating XOR:

```python
plain = bytes(
    c ^ key[i % 8]
    for i, c in enumerate(payload)
)
```

For example, decrypting `sample3.sav` produced readable game data such as:

```text
Ollary Wren
Needle of the Bureau / Points at your own signature.
Ivory dial-plate% / Twelve marks. Only nine of them tick.
Ghost-key% / Turns in locks...
...
S3D14t / Signal hovers below fifty...
Beneath the Widow's Bell
```

At this point, the "encrypted" save file was no longer really encrypted in the traditional sense. It was simply using an 8-byte repeating XOR key.

The challenge then shifted from cryptanalysis to **format reversing**.

---

# 9. Post-Exploitation: Reverse Engineering the Save Format

With the payload decrypted, I mapped the binary structure around the readable strings.

The beginning of the structure looked approximately like:

```text
u8       0x01
u32LE    ?
u8       name_len
bytes    player_name
bytes    player_stats      (~10 bytes)
u16LE    inventory_count
```

The inventory count immediately correlated with the payload growth:

```text
sample1    5 items
sample2    10 items
sample3    13 items
team_485   16 items
```

Each item then followed a structure similar to:

```text
u8        0x10
u8        item_index
u8        field_1
u8        field_2
u8        base_name_len
bytes     base_name
u8        suffix
u8        0x00
bytes     description
```

One useful observation was that the displayed item name was not always stored as a single string.

The suffix was a separate one-byte field:

```text
0x25  -> %
0x24  -> $
0x21  -> !
0x20  -> space
0x1c
0x1f
0x1a
...
```

That explained some otherwise strange-looking names.

For example, in `team_485.sav`:

```text
10 00 03 02 10 Ivory dial-plate % 00 ...
10 01 00 00 0e Ember-in-glass 1c 00 ...
10 02 01 00 0d 6-ward amulet 20 00 ...
...
10 0f 02 02 0f Blackbone flute 24 00 ...
```

The filename `sample1.sav` also contained an encoding edge case:

```text
Cracked séance disc
```

The `é` character appears as UTF-8:

```text
c3 a9
```

So a naïve byte-oriented string parser can split the field incorrectly. Parsing the format as UTF-8-aware text fixed that issue.

---

## 10. Finding the Hidden Message

The decrypted files were clearly designed to contain more than normal save-game data.

The strongest clue came from a lore entry in the team file:

```text
S1D12
```

The text explained that something in the reliquary was speaking through the items collected in a particular order:

> "First things first, I think."

That suggested testing an acrostic using the item names in their stored index order.

This turned out to be the intended extraction method.

### sample1

First letters of the five base item names:

```text
Talcum
Obsidian
Rusted
Cracked
Hair
```

Result:

```text
TORCH
```

### sample2

```text
Silver
Ivory
Lead
Vessel
Ember
Rusted
Marrow
Obsidian
Obsidian
Needle
```

Result:

```text
SILVERMOON
```

### sample3

```text
Needle
Ivory
Ghost
Hair
Talcum
Ember
Needle
Doubling
Silver
Silver
Obsidian
Obsidian
Needle
```

Result:

```text
NIGHTENDSSOON
```

Which reads naturally as:

```text
NIGHT ENDS SOON
```

That confirmed the extraction mechanism.

---

# 11. Team File — Token Recovery

Finally, I applied the same extraction to `team_485.sav`.

The 16 base item names were:

```text
Ivory
Ember
6-ward
Hair
Knotted
Ember
Doubling
Lead
Jarful
Zinc
Zinc
Widow's
Needle
Silver
Knotted
Blackbone
```

Taking the first character of each name gives:

```text
IE6HKEDLJZZWNSKB
```

This was a strong match for the challenge objective:

```text
length = 16
charset = [A-Z0-9]
```

The inventory count was also exactly:

```text
16
```

So the token length was not arbitrary.

I also tested the descriptions themselves:

```text
TWONUWSSSCCTPWUT
```

That did not form a meaningful message.

This is further evidence that the **item names**, not the descriptions, were the intended communication channel.

---

# 12. Verification

To avoid relying on a lucky manual extraction, I verified the entire process from the raw save files:

1. Parse the common 12-byte header.
2. Extract the encrypted payload.
3. Recover the 8-byte repeating XOR key.
4. Decrypt the payload.
5. Parse inventory records.
6. Sort items by their stored index.
7. Extract the first letter of every base item name.
8. Reconstruct the token.

Running that pipeline reproduced:

```text
IE6HKEDLJZZWNSKB
```

deterministically.

Therefore the final submission is:

```text
IE6HKEDLJZZWNSKB
```

or:

```text
POCTF{IE6HKEDLJZZWNSKB}
```

---

# 13. Methodology Summary

The challenge looked much harder at first because the `.sav` files were binary and the payload was intentionally noisy.

The important thing was not to jump straight into brute force.

The attack path was:

```text
File Recon
   ↓
Header Analysis
   ↓
Byte Statistics
   ↓
Repeated-Ciphertext Search
   ↓
Cipher/Mode Elimination
   ↓
Repeating-Key Length Deduction
   ↓
L = 8 Hypothesis
   ↓
Per-Residue Frequency Analysis
   ↓
8-byte XOR Key Recovery
   ↓
Save-Format Reversing
   ↓
Inventory Enumeration
   ↓
Lore Clue Analysis
   ↓
Acrostic Extraction
   ↓
16-character Token
```

The biggest breakthrough was the repeated 46-byte ciphertext blocks separated by exactly 48 bytes.

That observation effectively eliminated the more complicated cipher models and reduced the problem to a tiny repeating-XOR keyspace.

From there, the decrypted structure exposed the real trick: the challenge was hiding the token in the **ordered first letters of the item names**.

---

# 14. Solver Core

The key-recovery logic can be summarized with:

```python
def recover(data, L):
    keys = []

    for r in range(L):
        chunk = data[r::L]

        best_key = max(
            range(256),
            key=lambda k: score(bytes(b ^ k for b in chunk))
        )

        keys.append(best_key)

    return bytes(keys)
```

For this challenge:

```python
key = recover(payload, 8)

plain = bytes(
    c ^ key[i % 8]
    for i, c in enumerate(payload)
)
```

The entire cryptanalytic search is therefore only:

```text
8 × 256 candidates per file
```

After decryption, the remaining work is deterministic parsing and extraction.

---

## Final Flag

```text
POCTF{IE6HKEDLJZZWNSKB}
```
