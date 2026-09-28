# Letters Never Sent — Variant 082

**Category:** Crypto / Visual Stego / Classical Cipher  
**Challenge:** Letters Never Sent  
**Variant:** <code>variant_082</code>  
**Artifact:** <code>~/CTF/files/variant_082.png</code>  
**Author artifact:** Estate of Dr. H. Aldous Whitmore, Nov 1887  
**Result:** Solved

**Recovered key:** <code>REPOSE</code>

**Flag:**

~~~text
POCTF{2.485.BTOUVRJE7VELXAPI.JRAB35FRT3ONHQL7S5QM7BYDVQ}
~~~

---

## 1. Reconnaissance

The challenge provides a scanned letter and a ciphertext that already resembles a flag:

~~~text
CQNVN{2.485.DYQVTBVN7JLDVECW.GXSD35MNW3AFXBT7X5YG7DTBUY}
~~~

The image metadata is:

~~~text
PNG 820x1120
8-bit RGB
non-interlaced
SHA256:
01a7dbb1fe434bdaf33abee30e7cf0bc9a070354af0d611fe4ae2cbeba0d61ac
~~~

The letter is addressed to:

> To Admiral Sir Francis Beaufort, K.C.B. / Hydrographer to the Navy

The strongest clue is in the body:

> "that reciprocal tableau which bears your name"

That immediately points toward the **Beaufort cipher**, and the word **reciprocal** helps distinguish standard Beaufort from Vigenère and Variant Beaufort.

The ciphertext also suggests normal flag-format handling: braces, dots, and digits should remain untouched while alphabetic characters are transformed.

The remaining question is therefore: **where is the key?**

---

# 2. Image Enumeration — Finding the Hidden Key

The border contains very small words printed around the double rule, with several of them marked by red five-pointed stars.

At native resolution the text is too small to read reliably, so I cropped each side and upscaled it roughly 5–6× before transcribing it.

### Top — left to right

| Position | Label | Star |
|---|---|---|
| T0 | Rose | No |
| T1 | Rose | Yes |
| T2 | Fern | No |
| T3 | Swan | No |
| T4 | Elder | Yes |
| T5 | Tulip | No |

### Right — top to bottom

| Position | Label | Star |
|---|---|---|
| R0 | Poppy | No |
| R1 | Poppy | Yes |
| R2 | Harp | No |
| R3 | Willow | No |
| R4 | Marigold | No |
| R5 | Dove | No |

### Bottom — left to right

| Position | Label | Star |
|---|---|---|
| B0 | Swan | Yes |
| B1 | Carnation | No |
| B2 | Yarrow | No |
| B3 | Violet | No |
| B4 | Oak | Yes |
| B5 | Oak | No |

### Left — top to bottom

| Position | Label | Star |
|---|---|---|
| L0 | Tulip | No |
| L1 | Elder | Yes |
| L2 | Swan | No |
| L3 | Fern | No |
| L4 | Lily | No |
| L5 | Rose | No |

There are 24 labels in total and 6 starred entries.

Taking only the starred words gives:

~~~text
Rose
Elder
Poppy
Swan
Oak
Elder
~~~

Their initials are:

~~~text
R E P S O E
~~~

That is close to a meaningful word, but the order still needs to be solved.

---

# 3. Methodology — Recovering the Key Order

I tested the obvious ordering hypotheses:

- use the labels in their raw side-by-side order
- treat the initials as an anagram
- sort the starred words
- follow the border in a natural traversal
- extract another acrostic from the letter body
- use semantic information from the flower names

The strongest interpretation is to treat the page as a framed object and walk its border **clockwise**, starting at the top-left.

Traversal:

~~~text
Top    : left -> right
Right  : top -> bottom
Bottom : right -> left
Left   : bottom -> top
~~~

The starred entries then appear in this order:

~~~text
Rose   -> R
Elder  -> E
Poppy  -> P
Oak    -> O
Swan   -> S
Elder  -> E
~~~

Giving:

~~~text
REPOSE
~~~

This is the first major confirmation. <code>REPOSE</code> is a valid English word and fits the atmosphere of a letter dealing with death, rest, and the supernatural.

More importantly, it works against the ciphertext.

---

# 4. Cipher Identification — Why Standard Beaufort?

There are three closely related classical ciphers worth separating here.

### Vigenère

~~~text
C = P + K mod 26
~~~

### Standard Beaufort

~~~text
C = K - P mod 26
P = K - C mod 26
~~~

The same operation works in both directions, which is the reciprocal property hinted at by the challenge text.

### Variant Beaufort

~~~text
C = P - K mod 26
~~~

So the clue combination:

~~~text
Beaufort + reciprocal tableau
~~~

maps specifically to **standard Beaufort**.

The decryption rule we need is therefore:

~~~text
P = K - C mod 26
~~~

---

# 5. Key Handling

The ciphertext contains both alphabetic and non-alphabetic characters:

~~~text
A-Z
0-9
.
{ }
~~~

For this kind of flag-format classical cipher, the correct approach is to:

1. decrypt only <code>A-Z</code>
2. preserve digits, dots, and braces
3. advance the repeating key only when a letter is processed

If the key advanced across every character, the first <code>.</code> or digit would shift the key alignment and corrupt the rest of the message.

---

# 6. Exploitation — Beaufort Decryption

No external dependency is required.

~~~python
ct = 'CQNVN{2.485.DYQVTBVN7JLDVECW.GXSD35MNW3AFXBT7X5YG7DTBUY}'
key = 'REPOSE'

def beaufort(s, k):
    result = ''
    key_index = 0

    for ch in s:
        if 'A' <= ch <= 'Z':
            c = ord(ch) - 65
            kk = ord(k[key_index % len(k)]) - 65

            result += chr((kk - c) % 26 + 65)
            key_index += 1
        else:
            result += ch

    return result

pt = beaufort(ct, key)
print(pt)

assert beaufort(pt, key) == ct
~~~

Output:

~~~text
POCTF{2.485.BTOUVRJE7VELXAPI.JRAB35FRT3ONHQL7S5QM7BYDVQ}
~~~

---

# 7. Fast Validation — The Header Oracle

Before decrypting the entire string, the first five characters are enough to validate the key and cipher.

Using:

~~~text
P = K - C mod 26
~~~

we get:

| Cipher | Key | Plain |
|---|---|---|
| C | R | P |
| Q | E | O |
| N | P | C |
| V | O | T |
| N | S | F |

So:

~~~text
CQNVN -> POCTF
~~~

This is a very strong oracle. A correct key/cipher combination should immediately produce the expected challenge prefix.

---

# 8. Alternative Hypotheses

To make sure the result was not coincidental, I tested the obvious alternatives.

### Rotations of the recovered letters

~~~text
REPOSE -> POCTF{2.485.
EPOSER -> CZBXR{2.485.
POSERE -> NYFJE{2.485.
OSEREP -> MCRWR{2.485.
~~~

Only the intended ordering produces the expected flag header.

### Different cipher variants

Using the same key:

~~~text
Vigenère(REPOSE)          -> LMYHV{2.485.
Variant-Beaufort(REPOSE) -> TUCJF{2.485.
Standard Beaufort         -> POCTF{2.485.
~~~

Again, only standard Beaufort works.

### Using individual starred words

Keys such as:

~~~text
ROSE
ELDER
SWAN
OAK
POPPY
~~~

do not produce a valid flag.

The evidence therefore converges on:

~~~text
Key    = REPOSE
Cipher = Standard Beaufort
~~~

---

# 9. Verification

Several independent checks confirm the solution.

### Reciprocity check

Beaufort is reciprocal, so applying the same transformation to the plaintext must recreate the original ciphertext:

~~~text
beaufort(plaintext, key) == ciphertext
True
~~~

### Length preservation

The ciphertext and plaintext remain the same length:

~~~text
56 -> 56
~~~

Non-letter characters stay in the same positions.

### Key alignment

The plaintext only comes out correctly when the key advances over alphabetic characters rather than every byte/character.

### Header validation

The first five letters decrypt from:

~~~text
CQNVN
~~~

to:

~~~text
POCTF
~~~

### Visual-to-cryptographic consistency

The key is derived independently from the image before it is tested against the ciphertext. That makes the result much stronger than simply trying dictionary words until one happens to work.

---

# 10. Flag Discovery

The recovered plaintext is:

~~~text
POCTF{2.485.BTOUVRJE7VELXAPI.JRAB35FRT3ONHQL7S5QM7BYDVQ}
~~~

This is the final flag. No additional encoding or hidden layer was required.

---

# 11. Operator Notes

This challenge rewards attacking the **highest-signal evidence first**.

The practical path was:

~~~text
Image Recon
    ↓
Border Microtext Extraction
    ↓
Starred-Label Enumeration
    ↓
Clockwise Traversal
    ↓
REPOSE
    ↓
"Beaufort" + "reciprocal tableau"
    ↓
Standard Beaufort
    ↓
A-Z-only key progression
    ↓
CQNVN -> POCTF
    ↓
Full Decryption
    ↓
Reciprocity + Format Verification
~~~

The main lessons:

- Tiny visual annotations can be the actual key material.
- When the challenge says **reciprocal** and explicitly references Beaufort, standard Beaufort should be the first cipher to test.
- For classical ciphers using a flag wrapper, the first five characters provide a very fast validation oracle.
- Preserve non-letter characters and do not advance the key across them.
- If several clues are embedded spatially, test the natural document traversal before treating the extracted letters as an anagram.

---

## Reproduction Checklist

- [x] Hash and inspect <code>variant_082.png</code>
- [x] Crop and upscale the border microtext
- [x] Transcribe the 24 labels
- [x] Identify the 6 starred labels
- [x] Traverse the border clockwise
- [x] Recover <code>REPOSE</code>
- [x] Apply standard Beaufort: <code>P = K - C mod 26</code>
- [x] Preserve digits, dots, and braces
- [x] Advance the key only over <code>A-Z</code>
- [x] Validate <code>CQNVN -> POCTF</code>
- [x] Verify reciprocity
- [x] Submit the recovered flag

---

*Variant-specific: this writeup applies to <code>variant_082</code>. Other variants may use different star placements and produce different keys, but the same border-traversal methodology can be reused.*
