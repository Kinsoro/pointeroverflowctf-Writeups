# STEG 200 — The Invisible Text

**Category:** Steganography / Wave 1  
**Challenge:** The Invisible Text  
**Artifact:** invisible_text_485.py  
**Result:** Solved

**Technique:** Trailing-whitespace covert channel

**Flag:**

~~~text
POCTF{KPNBEMKAOMBAJPNG}
~~~

---

## 1. Overview

This challenge is a good example of steganography hiding in plain sight.

The supplied artifact is a Python source file. It reconstructs a Base64 + zlib payload and prints a large block of Unicode Braille characters. Running it produces what looks like a hidden image: a dithered human silhouette.

That is the decoy.

The real message is hidden in something most editors and diff tools normally ignore: trailing spaces and tabs at the ends of source lines.

The solving path was:

~~~text
File Recon
    ↓
Static Analysis
    ↓
Run the Python payload
    ↓
Inspect invisible whitespace
    ↓
Separate spaces from tabs
    ↓
Extract 7-bit chunks
    ↓
Recover ASCII
    ↓
POCTF{KPNBEMKAOMBAJPNG}
~~~

---

# 2. Scope and Integrity

The analysis was limited to:

~~~text
~/CTF/files/invisible_text_485.py
~~~

No network activity or external expansion was required. The file was treated as read-only evidence and executed locally.

SHA-256:

~~~text
d14909244cf1864c7b8ba1089c89a11d5866cab14ca6f7cd99f339fee2659b2b
~~~

The hash matched the challenge-provided value, confirming the expected team 485 artifact.

---

# 3. Reconnaissance

## 3.1 File triage

Initial enumeration:

~~~bash
ls -l ~/CTF/files
file ~/CTF/files/invisible_text_485.py
sha256sum ~/CTF/files/invisible_text_485.py
~~~

The target is a 4245-byte Python source file, small enough for direct static analysis.

## 3.2 Static analysis

The source has a straightforward structure:

| Lines | Observation |
|---|---|
| 9–10 | base64 and zlib imports |
| 12–14 | version/archive metadata |
| 18–63 | 44 Base64-like chunks |
| 65–72 | reconstruction and decoding |
| 74–77 | output routine |

The visible decode chain is:

~~~text
44 chunks
   ↓
join
   ↓
Base64 decode
   ↓
zlib decompress
   ↓
UTF-8 text
   ↓
print
~~~

There is no complicated obfuscation in the Python logic.

---

# 4. Dynamic Analysis — The Braille Decoy

Running the script:

~~~bash
python3 ~/CTF/files/invisible_text_485.py > /tmp/opencode/out.txt
wc -c /tmp/opencode/out.txt
~~~

produced 6469 bytes across 33 lines of Unicode Braille characters.

I converted the Braille characters using the standard 8-dot mapping. The output becomes a 130×132 bitmap, which renders as a halftone human silhouette.

It is visually convincing, but nothing useful appears at normal scale, enlarged scale, or inverted.

Searching the decoded Braille data also produced no POCTF or FLAG substring.

This made the Braille layer look much more like **cover art than the actual flag carrier**.

That was the point where I stopped treating the program output as the only payload and returned to the source itself.

---

# 5. Enumeration — Finding the Invisible Layer

The challenge title is a strong hint: look for something that is literally invisible.

I inspected the source while preserving whitespace:

~~~bash
cat -A ~/CTF/files/invisible_text_485.py | head -n 50
~~~

That immediately exposed long runs of spaces and tabs at the ends of several lines.

The structure was highly regular:

- lines 1–46 contain trailing spaces and/or tabs
- line 47 contains two trailing spaces
- lines 48–80 contain no trailing whitespace
- odd-numbered lines contain long trailers
- even-numbered lines often contain a single tab as filler

Total trailing whitespace:

~~~text
299 characters
~~~

That is far too structured to dismiss as accidental formatting.

## 5.1 Raw-byte verification

To rule out zero-width or other Unicode tricks, I checked the file bytes directly:

~~~bash
python3 -c "import pathlib; data=pathlib.Path('invisible_text_485.py').read_bytes(); print(sorted(set(data)))"
~~~

The meaningful whitespace bytes were:

~~~text
0x09 -> tab
0x0A -> newline
0x20 -> space
~~~

No zero-width spaces or non-breaking spaces were present.

So the covert channel is simply:

~~~text
space vs tab
~~~

---

# 6. Hypothesis Testing

Once the whitespace became visible, I tested several possible interpretations.

### Braille text

The Braille output does not behave like normal Grade-1 Braille. Its use of all eight dots and the rendered silhouette are more consistent with image data.

**Rejected.**

### Whitespace language

A space/tab program is an obvious possibility, but the pattern does not form a meaningful Whitespace-language program. The alternating filler is better explained as steganographic noise.

**Rejected.**

### Morse

Treating spaces and tabs as two Morse symbols did not produce valid framing or readable text.

**Rejected.**

### Entire whitespace stream as bytes

Decoding all 299 whitespace characters as one binary stream produced non-printable output.

**Rejected.**

### Inverted mapping

Swapping the bit values so space=1 and tab=0 also failed.

**Rejected.**

The remaining hypothesis was much cleaner: the long whitespace trailers contain fixed-width ASCII data.

---

# 7. Covert-Channel Analysis

The long trailers on the odd-numbered lines have a very deliberate structure.

Most of the line is padding spaces, followed by **seven meaningful whitespace characters**.

That immediately suggests 7-bit ASCII.

The mapping that works is:

~~~text
space = 0
tab   = 1
~~~

and the bits are read MSB-first.

### Example — line 1

The trailer contains:

~~~text
'   <TAB> <TAB>    '
~~~

The final seven whitespace characters decode to:

~~~text
1010000
~~~

which is:

~~~text
0x50 = 80 = P
~~~

### Example — line 3

The final seven bits are:

~~~text
1001111
~~~

which gives:

~~~text
79 = O
~~~

Another carrier line produces:

~~~text
1111011
~~~

which is:

~~~text
123 = {
~~~

At that point the encoding is effectively confirmed.

---

# 8. Exploitation — Recovering the Flag

The real payload is carried by the 23 odd-numbered lines from 1 through 45.

The even-numbered lines act as filler, making the file look uniformly messy and making the carrier lines less obvious.

The decoded characters are:

~~~text
01:P  03:O  05:C  07:T  09:F  11:{
13:K  15:P  17:N  19:B  21:E  23:M
25:K  27:A  29:O  31:M  33:B  35:A
37:J  39:P  41:N  43:G  45:}
~~~

Giving:

~~~text
POCTF{KPNBEMKAOMBAJPNG}
~~~

The structure is exactly what we want:

~~~text
POCTF
{
16 uppercase characters
}
~~~

---

# 9. Minimal Extractor

The extraction can be automated with a very small Python script:

~~~python
import pathlib

p = pathlib.Path("/home/isit/CTF/files/invisible_text_485.py")
lines = p.read_text(encoding="utf-8").splitlines()

flag = ""

for i in range(0, 46, 2):
    trailing = lines[i][len(lines[i].rstrip(" \t")):][-7:]

    bits = "".join(
        "0" if c == " " else "1"
        for c in trailing
    )

    flag += chr(int(bits, 2))

print(flag)
~~~

Output:

~~~text
POCTF{KPNBEMKAOMBAJPNG}
~~~

No brute force is required. The encoding rules are deterministic:

~~~text
space = 0
tab   = 1
7 bits per character
MSB-first
carrier = odd-numbered source lines
~~~

---

# 10. Verification

I verified the recovered flag instead of trusting a single printable result.

### Format

The output is 23 characters and matches the expected:

~~~text
POCTF{...}
~~~

layout.

### Character set

The inner token is:

~~~text
KPNBEMKAOMBAJPNG
~~~

which is exactly 16 uppercase characters.

### Reproducibility

Running the extractor again against the original source produces the same result.

### Program behaviour

The original Python script still exits cleanly because trailing spaces and tabs do not change the semantics of the code.

That is an important carrier property: the hidden data can be modified or inspected without affecting program execution.

### Decoy verification

The Base64 + zlib Braille layer consistently renders only the silhouette and does not contain the flag.

Therefore:

~~~text
Braille = decoy / cover layer
Whitespace = actual flag carrier
~~~

---

# 11. Methodology

The investigation followed a simple evidence-driven loop:

~~~text
OBSERVE → ANALYZE → TEST → UPDATE
~~~

### Preserve evidence

Hash the file first. When dealing with invisible characters, read the raw bytes or use tools that explicitly display whitespace.

### Prefer targeted enumeration

A command such as:

~~~bash
cat -A
~~~

was more valuable here than immediately running a generic steganography scanner.

### Separate facts from hypotheses

The fact was the systematic space/tab pattern.

The hypotheses were Braille text, Whitespace language, Morse, binary encoding, and finally 7-bit ASCII.

Each hypothesis was tested against the artifact.

### Maximize signal per action

A few focused commands were enough to identify both the visual decoy and the real covert channel.

Tooling used:

~~~text
sha256sum
file
cat -A
python3
PIL / image rendering
hexdump
~~~

No network enumeration or external research was needed.

---

# 12. Defensive / Detection Lessons

Trailing whitespace is a useful covert channel precisely because many editors, viewers, and code-review interfaces hide it.

For defenders and repository maintainers:

- use git diff --check to catch trailing whitespace
- consider pre-commit whitespace validation
- inspect suspicious source with tools that preserve invisible characters
- compare raw bytes when source integrity matters
- do not assume visible program output contains the only payload

The challenge also demonstrates a common steganography technique:

~~~text
convincing visible payload
        ↓
analyst focuses on it
        ↓
real secret remains elsewhere
~~~

Here, the Braille artwork provides enough visual substance to distract from the much simpler whitespace channel carrying the actual flag.

---

# 13. Reproduction Checklist

- [x] Verify the SHA-256 of invisible_text_485.py
- [x] Read the source without stripping whitespace
- [x] Run the script and inspect the Braille output
- [x] Confirm the Braille layer is only cover art
- [x] Enumerate trailing spaces and tabs
- [x] Identify the 23 carrier lines
- [x] Extract the final 7 whitespace characters from each
- [x] Decode space=0 and tab=1 as 7-bit ASCII
- [x] Recover POCTF{KPNBEMKAOMBAJPNG}
- [x] Re-run the extractor to confirm reproducibility

---

# 14. Final Flag

~~~text
POCTF{KPNBEMKAOMBAJPNG}
~~~

## Takeaway

The interesting part of this challenge was not the compressed Braille image. It was noticing that the source file contained **structured invisible state**.

**Recon** showed what the program did.  
**Dynamic analysis** exposed the Braille decoy.  
**Whitespace enumeration** revealed the real covert channel.  
**7-bit decoding** recovered the flag.

Sometimes the payload is not hidden in the pixels.

Sometimes it is hiding at the end of the line.
