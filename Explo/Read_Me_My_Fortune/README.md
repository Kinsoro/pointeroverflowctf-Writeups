# EXP 200 — Read Me My Fortune

**Category:** Exploitation  
**Challenge:** Read Me My Fortune  
**Result:** Solved

## Overview

This challenge was a Python formatting vulnerability disguised as a fortune-reading service.

The application accepted a user-supplied template and passed it to Python's `str.format()`. At the same time, the formatter was given a Python function object as one of its available values.

That combination exposed more than simple text substitution. The function object could be inspected through Python's object model, which eventually provided access to the module namespace containing the challenge flag.

The result was direct server-side flag disclosure.

## Reconnaissance

The challenge provided the main service source and runtime files. Reviewing the source first was enough to identify the important data flow:

```text
User template
    ↓
Python str.format()
    ↓
Formatting context
    ↓
Exposed Python function object
    ↓
Module-level state
    ↓
FLAG
```

The service used an interactive TCP protocol and required a valid challenge session. The flag was generated for the current team/session rather than being a simple static file.

No broad network enumeration was necessary.

## Vulnerability

The root cause was allowing untrusted input to act as a Python format string while exposing a complex Python object to the formatter.

The important distinction was:

- ordinary inputs were simple strings;
- the `elara` value was a function object;
- Python format strings can traverse object attributes and dictionary-style items;
- the challenge flag existed in the same module namespace.

This created an unintended path from attacker-controlled formatting input to sensitive server-side data.

## Validation

The behavior was first reproduced locally using the challenge's development mode.

The local result confirmed that the formatting context could reach the module-level flag.

The same behavior was then confirmed against the live challenge instance, where it disclosed the team-specific flag.

The live session credential is intentionally not included in this repository.

## Result

Recovered flag:

```text
POCTF{127.485.OYPQYO4ICKST2YU5.SYI25YQWOXOETKCYRXNB5BLWHD}
```

## Verification

The returned value matched the challenge context:

```text
Challenge ID: 127
Team ID:      485
Nonce:        OYPQYO4ICKST2YU5
```

The local and live behavior were consistent, confirming that the value was read from the server-side flag variable rather than guessed.

No authentication bypass, brute force, or privilege escalation was required.

## Impact

In a real application, this design could disclose more than a single flag.

Depending on the objects exposed to the formatting engine, similar weaknesses could reveal:

- application configuration;
- secrets or credentials;
- imported modules;
- internal runtime objects;
- other sensitive process data.

The ultimate impact depends on the application's runtime context and the objects reachable from the template.

## Remediation

The safest approach is to avoid treating untrusted input as a Python format program.

Recommended practices:

1. Use a restricted templating mechanism with an explicit allowlist.
2. Pass plain data instead of functions or modules.
3. Prevent arbitrary attribute and item traversal.
4. Keep sensitive values outside the rendering namespace.
5. Return generic errors to clients and log detailed exceptions server-side.

## Methodology Lesson

The key lesson from this challenge was to trace the **objects available to a rendering engine**, not only the visible input fields.

The useful workflow was:

```text
Read source
   ↓
Find the formatting sink
   ↓
Trace attacker-controlled input
   ↓
Inspect exposed object types
   ↓
Identify unintended object access
   ↓
Validate locally
   ↓
Confirm the challenge result
```

> When user input reaches a formatting or templating engine, inspect both the syntax being interpreted and the objects exposed to it.

## Final Flag

```text
POCTF{127.485.OYPQYO4ICKST2YU5.SYI25YQWOXOETKCYRXNB5BLWHD}
```
