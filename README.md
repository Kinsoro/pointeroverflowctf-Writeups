# PointerOverflow CTF 2026 — Writeups

![PointerOverflow CTF](https://github.com/user-attachments/assets/a9c52dd8-f704-43be-8809-c8e10489698b)

> A structured collection of **PointerOverflow CTF 2026** writeups, focused on practical vulnerability analysis, exploitation, reverse engineering, cryptography, digital forensics, and steganography.

## About

This repository documents challenges solved during PointerOverflow CTF 2026.

The goal is not only to record the final flags, but to preserve the reasoning and technical process behind each solve:

- reconnaissance and attack-surface identification;
- vulnerability discovery and root-cause analysis;
- exploitation and proof of concept;
- evidence-based verification;
- defensive lessons and remediation where relevant.

Each challenge is kept in its own directory with a dedicated `README.md` and supporting artifacts when applicable.

## Challenge Categories

| Category | Focus | Writeups |
|---|---|---|
| [Web Exploitation](Web/) | Web applications, APIs, GraphQL, authorization flaws | [The Shape of Query](Web/The_Shape_of_Query/) |
| [Exploitation](Explo/) | Exploit development and server-side vulnerabilities | [Read Me My Fortune](Explo/Read_Me_My_Fortune/) |
| [Cryptography](Crypto/) | Classical ciphers, cryptographic analysis, and related techniques | [Letters Never Sent](Crypto/Letters_Never_Sent/) |
| [Digital Forensics](Forensics/) | Browser artifacts, timelines, and evidence analysis | [Everything Left Open](Forensics/Everything_Left_Open/) |
| [Reverse Engineering](RE/) | Binary and program analysis | [EXCAVATION](RE/EXCAVATION/) |
| [Steganography](Steganography/) | Hidden data, whitespace channels, visual and layered stego | [The Invisible Text](Steganography/The_Invisible_Text/) |

More categories and challenges will be added as the CTF collection grows.

## Highlighted Techniques

The current writeups cover a range of offensive-security and analysis techniques, including:

```text
GraphQL BOLA / IDOR
Python format-string injection
Server-side data disclosure
Browser artifact analysis
Cipher analysis
Reverse engineering
Whitespace steganography
Layered payload investigation
```

## Approach

The writeups generally follow an evidence-driven workflow:

```text
Recon
  ↓
Understand the attack surface
  ↓
Identify interesting behavior
  ↓
Form a hypothesis
  ↓
Test and verify
  ↓
Exploit the intended primitive
  ↓
Document impact and remediation
```

The emphasis is on understanding **why** a vulnerability works, not just reproducing the final result.

## Repository Structure

```text
pointeroverflowctf-Writeups-2026/
├── Crypto/
├── Explo/
├── Forensics/
├── RE/
├── Steganography/
├── Web/
└── README.md
```

Each category contains challenge-specific directories rather than placing all writeups in the repository root.

## Selected Writeups

### Web — The Shape of Query

A GraphQL authorization flaw where the same `User` object was protected through one query path but exposed through another nested relationship.

[Read the writeup →](Web/The_Shape_of_Query/)

### Explo — Read Me My Fortune

A Python formatting vulnerability where attacker-controlled templates reached sensitive server-side state through the formatting context.

[Read the writeup →](Explo/Read_Me_My_Fortune/)

### Steganography — The Invisible Text

A layered steganography challenge combining a visible Braille decoy with a trailing-whitespace covert channel.

[Read the writeup →](Steganography/The_Invisible_Text/)

### Cryptography — Letters Never Sent

A visual and cryptographic challenge involving border microtext and Beaufort cipher analysis.

[Read the writeup →](Crypto/Letters_Never_Sent/)

### Digital Forensics — Everything Left Open

A browser-artifact investigation using Firefox session data, `mozLz4` decompression, and timeline analysis.

[Read the writeup →](Forensics/Everything_Left_Open/)

### Reverse Engineering — EXCAVATION

A reverse-engineering challenge documented through static and dynamic analysis.

[Read the writeup →](RE/EXCAVATION/)

## Notes

These reports are written for **CTF and authorized laboratory environments**. Techniques and tooling should only be applied to systems where testing is explicitly permitted.

Where live challenge credentials were involved, sensitive session material is intentionally excluded from the public repository.

---

**Maintained by [Kinsoro](https://github.com/Kinsoro)**  
**Focus:** Offensive Security · Infrastructure & Network Pentesting · Web Exploitation · CTF
