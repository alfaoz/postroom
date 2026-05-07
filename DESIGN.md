# POSTROOM

## NIO Mail System — Full Design Document

**Version:** 1.1 (post-decisions, pre-handoff)
**Status:** Foundation libraries complete; service implementations pending
**Authority:** N.N.A. (National Network Authority)

---

## 0.1 Revision history

**v1.1 — pre-handoff revisions.** After the original v1.0 spec was finalized, the following decisions were made and supersede earlier text. Where this document still contains pre-revision text (older numbers in long-form descriptions), section 0.2 below is authoritative.

## 0.2 Authoritative decisions (override anywhere else in the doc)

These are the final decisions. If the body of the document disagrees, this section wins.

### Limits
- **No per-mailbox message cap.** Mailboxes grow without bound. Trash auto-purges after 14 days, sent folder auto-prunes oldest after 500.
- **Subject length:** 100 chars max (not 200).
- **Body length:** 2500 chars max (not 4000).
- **Recipients per send:** unlimited (no `MAX_RECIPIENTS` cap).
- **Audit log on registry:** 1000 entries before rotation.
- **Audit log on mail server:** 500 entries before rotation.

### N.N.A. fee structure
The N.N.A. share is an **additional surcharge** on every fee line, paid in addition to the base fee. Final fee table:

| Action | Base | + N.N.A. share | Total |
|---|---|---|---|
| Application | 8ƒ | 3ƒ | **11ƒ** |
| Registration | 48ƒ | 3ƒ | **51ƒ** |
| Renewal | 12ƒ | 3ƒ | **15ƒ** |
| Transfer | 8ƒ | 3ƒ | **11ƒ** |

A new domain registration costs **62ƒ** at the counter (11 + 51).

### Office layout
The N.N.A. office has **only one computer**: `NNA_STAFF` (the staff terminal). There is no separate public-facing kiosk. Players walk up to a counter, talk to the on-duty staff member (a player), and the staff member operates the terminal on their behalf. When no staff is logged in, the terminal displays an "Office Closed" screen.

### Currency
Symbol `ƒ` (fluorin) for display in human-readable contexts. Lua code uses the ASCII string `"f"` because CC fonts may not render `ƒ` cleanly. Same currency as the airport project (cross-system economy).

### Domain naming
- 2–16 chars (not 3–16)
- Lowercase ASCII letters and digits only

### Reserved-but-not-issued vs issued
- **Issued at v1 launch:** `gov`, `nna`, `nta`, `nga`, `nmail`, `common`
- **Reserved (not issued):** `nhsa`, `nfa`, `nra`, `nwa`, `nea`, `nba`, `nja`, `nma`, `nca`, `mil`, `court`, `treasury`, plus all system local-parts

### Public mail brands
Two are operated by the N.N.A.: `@nmail` (National Mail) and `@common`. Each runs on its own server (`NMAIL_SRV`, `COMMON_SRV`), separate physical computers from `NNA_REG`.

### Bounce semantics
**Bounce immediately, no retry.** If a destination domain server is offline (no recent heartbeat), mail to it bounces in real-time back to the sender. No spool, no retry queue.

### Encryption
- **HMAC-SHA256** for message authentication on all cross-computer traffic.
- **AES-128-CBC** for message body encryption when bodies cross domain boundaries.
- Pure-Lua implementations, both verified against published test vectors.

### Abuse / rate-limiting
- No rate limits in v1.
- No abuse reporting flow in v1.
- Manual revocation only, by N.N.A. admin/staff with appropriate permissions.

### Staff
- N.N.A. staff are players assigned via permission flags on the registry.
- Single concurrent staff session at a time. New login boots prior session.
- Office is "closed" (terminal locked) when no staff is logged in.

### Privacy disclosure
Domain owners can read all mail at their domain. This is by design and **clearly disclosed at signup** on private domains. Users wanting privacy use `@nmail` or `@common`. The N.N.A. does not read user mail at the public domains.

---

## 0. Document Overview

This document describes the full design of **Postroom**, a federated email-style messaging system implemented in ComputerCraft. It is intended to be complete enough that the system can be built directly from it, without requiring further design decisions.

The document is structured as:

- **Section 1** — System overview and design principles
- **Section 2** — Topology (every computer in the system)
- **Section 3** — Network protocol specification
- **Section 4** — Data model (what's stored where)
- **Section 5** — Cryptography and authentication
- **Section 6** — User flows (every interaction, end to end)
- **Section 7** — Visual identity (palettes, screens, tone)
- **Section 8** — Naming and identifiers
- **Section 9** — Pricing and economics
- **Section 10** — Lifecycle and edge cases
- **Section 11** — Build order
- **Section 12** — Future considerations

---

## 1. System Overview

### 1.1 What Postroom is

Postroom is a federated mail system. Players use a client app (the **PR client**) to send messages to other players addressed by `username@domain` notation. Domains are namespaces for accounts; each domain runs on its own mail server computer.

There are two kinds of domains:

- **Public domains** (currently `@nmail` and `@common`) — operated by the N.N.A. itself, allowing anyone to self-register an account.
- **Private domains** (e.g. `@sundown`, `@wbia`) — operated by their owners, with accounts created by the domain owner only.

The **N.N.A.** (National Network Authority) is the central regulator. It maintains the domain registry, routes cross-domain mail, and operates the public mail servers. It also operates a physical office where a player-staffed terminal handles new domain applications, renewals, transfers, and revocations.

### 1.2 Design principles

1. **Centralized registry, distributed delivery.** The N.N.A. is the only authority for who owns what domain, but mail bodies live on the destination domain server, not the registry.

2. **Physical presence has weight.** Important actions (registering a domain, transferring ownership, paying renewals) require visiting the N.N.A. office and being processed by a player-staff member. Routine actions (sending mail, creating accounts at public domains) are self-serve.

3. **Domain owners can read their users' mail.** This is by design and clearly disclosed at signup. Users who want privacy use `@nmail` or `@common`. The N.N.A. operates `@nmail`/`@common` and does not read user mail.

4. **No retry queue.** If a destination domain is offline, mail bounces immediately. This makes the network's state legible and gives domain operators a clear incentive to maintain uptime.

5. **HMAC + AES.** Federation traffic is signed with HMAC and bodies are AES-encrypted. Not RSA-grade security, but enough to make the system feel real and resist casual sniffing.

6. **One client app, multiple skins.** The PR client is one program; it reskins itself based on which server it's connected to.

### 1.3 What Postroom is *not*

- Not real SMTP/IMAP. The wire format is custom.
- Not federated across servers (the N.N.A. is the only registry).
- No attachments, no labels, no threading by message ID, no multi-folder organization beyond Inbox/Sent/Trash.
- No mobile/pocket clients in v1 (could be added; pocket graphics-mode is unstable).

---

## 2. System Topology

### 2.1 Required computers

The minimum viable Postroom deployment uses **five computers**:

| ID | Role | Where it lives |
|---|---|---|
| `NNA_REG` | Registry server (authority, routing) | N.N.A. office, staff-only access |
| `NNA_STAFF` | Staff terminal | N.N.A. office counter |
| `NMAIL_SRV` | `@nmail` mail server | N.N.A. campus |
| `COMMON_SRV` | `@common` mail server | N.N.A. campus (separate machine) |
| One private domain server | Example: `@sundown` server | Owner's own building |

Plus client computers as needed (any modemmed computer can run the PR client).

### 2.2 Computer roles

#### `NNA_REG` — National Network Authority Registry

**Purpose:** Central authority. Holds the domain registry, install tokens, server keys, audit log, billing log, renewal schedule.

**Stores:** No user mail. Registry data only.

**Network identity:** Hosts itself on protocol `POSTROOM_NET` as `NNA_REG`.

**Peripherals:**
- One wireless modem (mandatory).
- Optional: a printer for printing internal admin reports.

**Access:** Physically inaccessible to non-staff. Located behind a wall or in a back room.

#### `NNA_STAFF` — Staff Terminal

**Purpose:** Clerk's workstation. Used by the on-duty player-employee to process domain applications, renewals, transfers, and revocations.

**Stores:** No persistent state of its own (other than recent staff sessions). All state is on `NNA_REG`.

**Network identity:** Talks to `NNA_REG` over `POSTROOM_NET`.

**Peripherals:**
- One wireless modem (mandatory).
- One disk drive (mandatory — for writing install floppies).
- One printer (mandatory — for certificates and receipts).

**Access:** Physically located at the office counter, facing the staff side. Players walk up to a desk, the staff sits behind it.

**Behavior when no staff logged in:** Displays a "Office closed — please return when staff is on duty" screen. Cannot process any requests until a staff member logs in.

#### `NMAIL_SRV` — National Mail Server

**Purpose:** Operates the `@nmail` domain. Handles self-registration, accounts, mail storage, sending, receiving.

**Stores:** All `@nmail` user accounts, mailboxes, messages.

**Network identity:** Hosts on `POSTROOM_NET` as `NMAIL_SRV`. Registered with `NNA_REG` as the operator of `@nmail`.

**Peripherals:**
- One wireless modem (mandatory).

**Access:** Logically owned by the N.N.A. but a separate physical machine from `NNA_REG`. Can be co-located.

#### `COMMON_SRV` — Common Mail Server

**Purpose:** Operates the `@common` domain. Identical role to `NMAIL_SRV`, different branding.

**Stores:** All `@common` user accounts, mailboxes, messages.

**Network identity:** Hosts on `POSTROOM_NET` as `COMMON_SRV`.

**Peripherals:**
- One wireless modem (mandatory).

#### Private domain servers (e.g. `@sundown`)

**Purpose:** Operates one privately-owned domain.

**Stores:** All accounts, mailboxes, messages for that domain.

**Network identity:** Hosts on `POSTROOM_NET` as the domain name (e.g. `SUNDOWN_SRV`). Registered with `NNA_REG` via install token.

**Peripherals:**
- One wireless modem (mandatory).

**Access:** Owned and operated by the domain owner. Located in their own build.

### 2.3 Client computers

The PR client app runs on any modemmed computer. It does not need to be provisioned; it just needs the `pr` program installed (e.g. via floppy distribution or `pastebin get`).

The client connects to whichever mail server hosts the user's account, based on the domain part of the address used at login.

### 2.4 Network diagram

```
                        ┌─────────────────────┐
                        │      NNA_REG        │
                        │  Registry & Router  │
                        │   (no user mail)    │
                        └──────────┬──────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
       ┌──────┴──────┐      ┌──────┴──────┐      ┌─────┴──────┐
       │ NMAIL_SRV   │      │ COMMON_SRV  │      │ SUNDOWN_SRV│
       │  @nmail     │      │  @common    │      │  @sundown  │
       └──────┬──────┘      └──────┬──────┘      └─────┬──────┘
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   │
                            (modem network)
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
       ┌──────┴──────┐      ┌──────┴──────┐      ┌─────┴──────┐
       │ PR Client   │      │ PR Client   │      │ NNA_STAFF  │
       │  (Alice)    │      │  (Bob)      │      │  Terminal  │
       └─────────────┘      └─────────────┘      └────────────┘
```

---

## 3. Network Protocol

### 3.1 Wire format

Every message on the network is a Lua table sent over rednet on protocol `POSTROOM_NET`:

```lua
{
  type        = "req" | "resp",
  proto       = "POSTROOM/REG" | "POSTROOM/USR",
  station     = "<sender_station_id>",
  rid         = "<request_id>",          -- only on req; echoed in resp
  nonce       = "<unique_string>",        -- replay protection
  action      = "<action_name>",          -- only on req
  payload     = { ... },                  -- plaintext metadata
  body        = "<aes_ciphertext>",       -- optional, encrypted contents
  ok          = true | false,             -- only on resp
  data        = { ... },                  -- only on resp, on success
  error       = "<error_code>",           -- only on resp, on failure
  sig         = "<hmac_hex>",             -- HMAC over canonical(everything else)
}
```

**Field rules:**

- `proto` distinguishes the two sub-protocols. `POSTROOM/REG` is server-to-registry; `POSTROOM/USR` is client-to-server.
- `station` identifies the sender — for servers it's the station name (e.g. `SUNDOWN_SRV`); for clients it's `CLIENT:<computer_id>`.
- `rid` is a unique-per-conversation request ID, echoed back in the response.
- `nonce` is a unique-per-message string. Servers track recent nonces (last 5 minutes) and reject replays.
- `payload` is plaintext metadata visible to intermediate routers (sender, recipient, subject for mail; action params for everything else).
- `body` is optional. Used for AES-encrypted message contents in mail delivery.
- `sig` is an HMAC of the canonicalized message (excluding `sig` itself), proving the sender holds the shared secret.

### 3.2 Two protocols

**`POSTROOM/REG`** — used between domain servers and `NNA_REG`, and between `NNA_STAFF` and `NNA_REG`. Authenticated with each station's permanent shared secret (issued at install time for domain servers, set up manually for staff terminal).

**`POSTROOM/USR`** — used between clients and any mail server. Authenticated with the user's session token (a per-login secret derived from the password hash).

### 3.3 `POSTROOM/REG` actions

#### Sent by domain servers to `NNA_REG`:

**`heartbeat`**
- Payload: `{ server_id, domain, last_activity_at }`
- Response: `{ ok, registry_time, registry_day }`
- Frequency: every 60 in-game seconds.
- Purpose: Lets registry know server is online. If registry hasn't received a heartbeat in 3 minutes, the server is considered offline and mail is bounced.

**`route_mail`**
- Payload: `{ from, to_list, subject, sent_at }`
- Body: `{ encrypted message body + sender metadata }`
- Response: `{ ok, delivery_results: [{recipient, status, reason?}] }`
- Purpose: Sending server asks registry to deliver to one or more cross-domain recipients. Registry looks up each recipient's domain server, calls `deliver_mail` if online, returns failure codes if not.

**`consume_install_token`** (special — used during install)
- Payload: `{ token, computer_id, requested_op_username }`
- Response: `{ ok, shared_secret, domain, op_initial_password, registry_settings }`
- Purpose: Bootstraps a new domain server. One-time use per token.

**`update_branding`**
- Payload: `{ display_name, theme_color_palette, sign_off }`
- Response: `{ ok }`
- Purpose: Domain owner updates their public-facing brand info; registry mirrors it for consumers.

#### Sent by `NNA_REG` to domain servers:

**`deliver_mail`**
- Payload: `{ from, to_list, subject, sent_at, message_id }`
- Body: `{ encrypted message contents }`
- Response: `{ ok, accepted_recipients: [...] }`
- Purpose: Registry pushes a message to a destination domain server. Server stores it in each recipient's inbox.

**`notify_revoked`**
- Payload: `{ domain, reason }`
- Response: `{ ok }`
- Purpose: Registry tells a domain server it has been revoked. Server should refuse new mail and shut down on next reboot.

**`notify_renewal`**
- Payload: `{ domain, days_until_expiry, fee_due }`
- Response: `{ ok }`
- Purpose: Registry tells a domain server about an upcoming or overdue renewal. Server forwards to `op@<domain>`'s inbox as a system message.

**`notify_suspended`**
- Payload: `{ domain, reason }`
- Response: `{ ok }`
- Purpose: Registry tells a server it's entered suspension. Server stops accepting new mail.

#### Sent by `NNA_STAFF` to `NNA_REG`:

**`staff_login`**
- Payload: `{ username, password_hash, terminal_computer_id }`
- Response: `{ ok, session_token, staff_display_name }`

**`staff_logout`**
- Payload: `{ session_token }`
- Response: `{ ok }`

**`register_domain`** (creates a new pending-install domain)
- Payload: `{ session_token, domain_name, applicant_realname, op_username, fee_paid }`
- Response: `{ ok, install_token, expires_day }`

**`renew_domain`**
- Payload: `{ session_token, domain_name, fee_paid }`
- Response: `{ ok, new_expires_day }`

**`transfer_domain`**
- Payload: `{ session_token, domain_name, new_owner_realname, new_op_password }`
- Response: `{ ok }`

**`revoke_domain`**
- Payload: `{ session_token, domain_name, reason }`
- Response: `{ ok }`

**`list_domains`**
- Payload: `{ session_token, filter? }`
- Response: `{ ok, domains: [...] }`

**`list_pending_apps`**
- Payload: `{ session_token }`
- Response: `{ ok, pending: [...] }` — currently always empty since registration is staff-initiated, but reserved for future.

**`audit_query`**
- Payload: `{ session_token, since_day?, kind? }`
- Response: `{ ok, entries: [...] }`

#### Sent by anyone (no auth):

**`domain_status`**
- Payload: `{ domain }`
- Response: `{ ok, registered, status?, server_online?, branding? }`
- Purpose: Public lookup. Used by clients to find which server hosts a domain at login time.

**`list_public_domains`**
- Payload: `{}`
- Response: `{ ok, domains: [{ name, server_id, branding }, ...] }`
- Purpose: Used by client at "create account" time to populate the domain picker.

### 3.4 `POSTROOM/USR` actions

All client-server actions. Auth by session token (`session_token` in payload, plus HMAC).

**`register`**
- Payload: `{ username, password_hash, computer_id }`
- Response: `{ ok, session_token, expires_at } | { error, "USERNAME_TAKEN" | "INVALID_USERNAME" | "DOMAIN_CLOSED" }`
- Purpose: Self-registration. Only succeeds on public domains.

**`login`**
- Payload: `{ username, password_hash, computer_id }`
- Response: `{ ok, session_token, expires_at, must_change_password? } | { error, "BAD_CREDENTIALS" }`

**`logout`**
- Payload: `{ session_token }`
- Response: `{ ok }`

**`change_password`**
- Payload: `{ session_token, current_password_hash, new_password_hash }`
- Response: `{ ok } | { error, "BAD_CREDENTIALS" | "WEAK_PASSWORD" }`

**`account_info`**
- Payload: `{ session_token }`
- Response: `{ ok, username, domain, created_day, last_login_day, msg_count, unread_count }`

**`list_inbox`**
- Payload: `{ session_token, folder?, limit?, before_id? }`
- Response: `{ ok, messages: [{ id, from, subject, sent_day, unread, has_attachments? }, ...] }`
- Folder defaults to `inbox`. Can be `sent`, `trash`.

**`read_message`**
- Payload: `{ session_token, id }`
- Response: `{ ok, message: { id, from, to, subject, body, sent_day, sent_at } }`
- Side effect: marks message as read.

**`mark_read`**
- Payload: `{ session_token, id, read }`
- Response: `{ ok }`

**`delete_message`**
- Payload: `{ session_token, id }`
- Response: `{ ok }` (moves to trash; trash auto-purges after 14 days)

**`send`**
- Payload: `{ session_token, to: [...], subject, body }`
- Response: `{ ok, message_id, delivery_results: [{ recipient, status, reason? }] }`
- Server stores in sent folder, delivers locally for same-domain recipients, calls `route_mail` on registry for cross-domain.

**`search`**
- Payload: `{ session_token, query, folder? }`
- Response: `{ ok, messages: [...] }`

**`list_local_users`**
- Payload: `{ session_token, prefix? }`
- Response: `{ ok, users: [...] }`
- Purpose: Autocomplete in compose. Returns same-domain users only.

#### Domain-admin actions (require `op@` or deputy-flagged session):

**`admin_create_user`**
- Payload: `{ session_token, username, initial_password_hash }`
- Response: `{ ok, username }`

**`admin_delete_user`**
- Payload: `{ session_token, username, confirm: "DELETE" }`
- Response: `{ ok }`

**`admin_reset_password`**
- Payload: `{ session_token, username, new_password_hash }`
- Response: `{ ok }`

**`admin_view_user_inbox`**
- Payload: `{ session_token, username, folder?, limit? }`
- Response: `{ ok, messages: [...] }`
- Logged in audit. User is *not* notified.

**`admin_view_message`**
- Payload: `{ session_token, username, message_id }`
- Response: `{ ok, message: {...} }`
- Logged in audit.

**`admin_set_branding`**
- Payload: `{ session_token, branding: {...} }`
- Response: `{ ok }`
- Server forwards to registry via `update_branding`.

**`admin_domain_stats`**
- Payload: `{ session_token }`
- Response: `{ ok, user_count, msg_count, storage_used, recent_activity }`

### 3.5 Error codes

| Code | Meaning |
|---|---|
| `OK` | Success |
| `AUTH_FAILED` | Bad signature, invalid session, or wrong password |
| `INVALID_REQUEST` | Malformed request structure |
| `UNKNOWN_ACTION` | Action not recognized |
| `UNKNOWN_DOMAIN` | Domain not in registry |
| `UNKNOWN_RECIPIENT` | Username doesn't exist at that domain |
| `DOMAIN_OFFLINE` | Domain server hasn't sent heartbeat in window |
| `DOMAIN_SUSPENDED` | Domain is in non-payment suspension |
| `DOMAIN_REVOKED` | Domain has been revoked |
| `USERNAME_TAKEN` | Account name already exists |
| `INVALID_USERNAME` | Doesn't meet format rules |
| `DOMAIN_CLOSED` | Public registration not allowed on this domain |
| `BAD_CREDENTIALS` | Login failed |
| `INSUFFICIENT_PERMISSIONS` | User can't perform this action |
| `RATE_LIMITED` | Reserved for future |
| `INTERNAL_ERROR` | Server fault |

### 3.6 Routing semantics

When a user sends a message:

1. Client calls `send` on its home server.
2. Home server stores the message in its `messages` table, adds to sender's `sent` folder.
3. For each recipient:
   - If recipient is `username@<own_domain>`: deliver locally, add to recipient's inbox.
   - If recipient is on a different domain: add to a list of cross-domain deliveries.
4. If any cross-domain recipients: home server calls `route_mail` on `NNA_REG`, passing the encrypted body.
5. `NNA_REG` for each cross-domain recipient:
   - Looks up the destination domain.
   - If online (recent heartbeat) and active (not revoked/suspended): calls `deliver_mail` on the destination server.
   - Otherwise: marks that recipient as failed.
6. `NNA_REG` returns per-recipient status to the home server.
7. Home server returns aggregated status to the client.
8. For each failed recipient: home server creates a bounce message in the *sender's* inbox from `pm@<sender_domain>`, with the failure reason.

### 3.7 Bounce semantics (no retry)

Bounces are immediate. There is no spool, no queue, no retry. If the destination is offline at send time, the recipient does not get the message.

The bounce message:
- From: `pm@<sender_domain>`
- To: original sender
- Subject: `Undeliverable: <original subject>`
- Body: explains which recipients failed and why (`@sundown is offline`, `bob@nmail does not exist`, etc.)

Bounces themselves never bounce. If a bounce can't be delivered, it's silently dropped.

### 3.8 Heartbeat

Every domain server (including `NMAIL_SRV` and `COMMON_SRV`) sends a `heartbeat` to `NNA_REG` every 60 seconds. The registry tracks `last_heartbeat_at` per domain.

A domain is considered "online" if `now - last_heartbeat_at < 180 seconds` (3 minutes). If a domain misses heartbeats and is considered offline, mail to it bounces.

The registry's daily tick (see lifecycle, Section 10) checks for domains that have been offline for more than 24 hours and sends a notice to the owner via `pm@nna`.

---

## 4. Data Model

### 4.1 `NNA_REG` state

```lua
state = {
  domains = {
    -- key: domain name (lowercase)
    [name] = {
      name              = "sundown",
      owner_username    = "barkeep",         -- the op@<domain> username
      owner_realname    = "Bob",             -- player name for record
      registered_day    = 141,
      expires_day       = 189,               -- bi-seasonal renewal
      status            = "ACTIVE",          -- ACTIVE | SUSPENDED | REVOKED | PENDING_INSTALL
      server_id         = 47,                -- nil while pending install
      shared_secret     = "<hex>",           -- nil while pending install
      branding = {
        display_name    = "The Sundown Club",
        theme_palette   = { ... },           -- CC: Graphics palette
        sign_off        = "Cheers · Sundown",
      },
      last_heartbeat_at = 1700000000,
      last_heartbeat_day = 142,
      created_by_staff  = "alice",
      activity = {
        messages_routed = 0,                 -- counter, optional
      },
    },
  },

  install_tokens = {
    [token] = {
      token             = "ABCDEFGH12345678",
      domain_name       = "sundown",
      requested_op      = "barkeep",
      issued_day        = 141,
      expires_day       = 148,
      status            = "PENDING",         -- PENDING | CONSUMED | EXPIRED
      issued_by_staff   = "alice",
      consumed_by_id    = nil,               -- computer ID after consumption
      consumed_day      = nil,
    },
  },

  staff_accounts = {
    [username] = {
      username          = "alice",
      password_hash     = "<hex>",
      display_name      = "Alice",
      added_day         = 100,
      added_by          = "admin",
      active            = true,
      last_login_day    = 142,
    },
  },

  staff_sessions = {
    [token] = {
      token             = "<hex>",
      username          = "alice",
      terminal_id       = 12,
      created_at        = 1700000000,
      last_used_at      = 1700000000,
      expires_at        = 1700003600,
    },
  },

  reserved_names = {
    -- Government domains (issued and unissued)
    "gov", "nna", "nta", "nga", "nhsa",
    "nfa", "nra", "nwa", "nea", "nba", "nja",
    "nma", "nca", "mil", "court", "treasury",
    -- Public mail domains
    "nmail", "common",
    -- System reserved
    "admin", "system", "abuse", "postmaster",
    "root", "public", "noreply", "op", "pm",
  },

  public_domains = {
    -- Domains where self-registration is allowed
    { domain = "nmail",  server_id = 23 },
    { domain = "common", server_id = 31 },
  },

  audit_log = {
    -- newest last; trimmed at 1000 entries
    {
      day = 141,
      time = 1700000000,
      actor = "STAFF:alice",
      action = "REGISTER_DOMAIN",
      target = "sundown",
      details = "Application fee 8f, registration fee 48f received.",
    },
  },

  billing_log = {
    -- All fees collected, append-only
    {
      day = 141,
      domain = "sundown",
      fee_type = "APPLICATION",
      amount = 8,
      processed_by = "STAFF:alice",
    },
  },

  counters = {
    domains_registered = 0,
    install_tokens_issued = 0,
    messages_routed = 0,
  },
}
```

### 4.2 Mail server state (`NMAIL_SRV`, `COMMON_SRV`, private domain servers)

All mail servers share the same state shape.

```lua
state = {
  domain_meta = {
    domain_name       = "nmail",
    server_id         = 23,
    shared_secret     = "<hex>",             -- with NNA_REG
    is_public_server  = true,                -- enables self-registration
    branding = {
      display_name    = "National Mail",
      theme_palette   = { ... },
      sign_off        = "— NIO Mail Service",
    },
    install = {
      installed_day   = 100,
      install_token   = "<consumed>",
      registry_id     = "NNA_REG",
    },
  },

  users = {
    -- key: username (lowercase, unique within domain)
    [username] = {
      username          = "alice",
      display_name      = "Alice",           -- optional, defaults to username
      password_hash     = "<hex>",
      created_day       = 100,
      last_login_day    = 142,
      must_change_password = false,
      is_op             = false,             -- only true for op@<domain>
      is_deputy         = false,             -- can perform admin actions
      is_system         = false,             -- pm/abuse/noreply
      storage_used_msgs = 12,
    },
  },

  messages = {
    -- key: message ID
    [id] = {
      id                = "MSG-0001",
      from              = "alice@nmail",
      to                = { "bob@sundown" },
      subject           = "Hi",
      body              = "Hello world!",
      sent_at           = 1700000000,
      sent_day          = 141,
      origin_server     = nil,               -- nil if originated locally
      delivered_to      = { "bob@sundown" }, -- which recipients got it
    },
  },

  mailboxes = {
    -- key: username
    [username] = {
      inbox = {
        { msg_id = "MSG-0001", unread = true,  received_at = 1700000000 },
      },
      sent = {
        { msg_id = "MSG-0002", sent_at = 1700000100 },
      },
      trash = {
        { msg_id = "MSG-0003", deleted_at = 1700000200 },
      },
    },
  },

  sessions = {
    -- key: session token
    [token] = {
      token             = "<hex>",
      username          = "alice",
      computer_id       = 12,
      created_at        = 1700000000,
      last_used_at      = 1700000000,
      expires_at        = 1700604800,        -- 7 in-game days
    },
  },

  audit_log = {
    -- For ops only; rotates at 500 entries
    {
      day = 141,
      time = 1700000000,
      actor = "op",
      action = "VIEW_USER_INBOX",
      target = "bartender",
      details = "Read 5 messages.",
    },
  },

  counters = {
    next_msg_id = 1,
    total_messages = 0,
    total_users = 0,
  },
}
```

### 4.3 Reserved system accounts

Every domain server, on initialization, creates these accounts automatically:

- **`op@<domain>`** — domain owner. Has admin powers. Only one per domain. Created on install with a temp password.
- **`pm@<domain>`** — postmaster. System sender; no human can log in. Used for bounces, system notices, welcomes.
- **`abuse@<domain>`** — abuse reports. Reserved for future use; currently inert.
- **`noreply@<domain>`** — for transactional sends that shouldn't be replied to. System-only sender.

These four local-parts cannot be assigned to regular users.

### 4.4 Client local state

```lua
state = {
  session = {
    username    = "alice",
    domain      = "nmail",
    server_id   = 23,
    token       = "<hex>",
    expires_at  = 1700604800,
  },

  cache = {
    inbox       = { ... },                    -- last fetched, expires after 15s
    cache_at    = 1700000000,
  },

  ui = {
    current_folder = "inbox",
    selected_index = 1,
    scroll = 0,
  },

  remembered_servers = {
    -- For convenience: addresses logged into recently
    { username = "alice", domain = "nmail", server_id = 23 },
  },
}
```

The client persists only `session` and `remembered_servers` to disk. Cache is in-memory only.

### 4.5 What's logged where

| Log location | Contents |
|---|---|
| `NNA_REG` audit | All staff actions, all install token operations, all domain lifecycle events. |
| `NNA_REG` billing | Every fee collected. Append-only. |
| Mail server audit | Logins, password changes, sends (sender + day + recipient count, NOT body), admin actions. |
| Client | Nothing logged. |

### 4.6 Storage limits

- **Per user:** 500 messages across all folders. New mail beyond this rejects with `MAILBOX_FULL`. (Future: implement; for now, soft warning.)
- **Trash auto-purge:** messages in trash older than 14 in-game days are permanently deleted.
- **Sent folder cap:** 500 messages, oldest auto-deleted.
- **Audit log on registry:** 1000 entries, rotated.
- **Audit log on mail server:** 500 entries, rotated.

---

## 5. Cryptography & Authentication

### 5.1 Threat model

The threat model is a friend on the same Minecraft server with computer access:

- Can sniff modem traffic.
- Can run their own computer with arbitrary code.
- Cannot break out of CC's Lua sandbox or read files on other computers physically.
- Is not a sophisticated attacker — won't brute-force keyspaces, but might try obvious replay or impersonation.

The system aims to be **plausibly secure** against this: tamper-evident, replay-protected, body confidentiality in transit. Not crypto-grade.

### 5.2 Primitives

**HMAC** — used for message authentication. Implemented as HMAC-SHA256 in pure Lua. (~150 lines for a SHA256 + HMAC wrapper, runs at hundreds of HMACs/sec on a CC computer — fast enough.)

**AES-128 CBC** — used for body encryption. Pure Lua implementation (~250 lines). Slow but adequate for mail volumes.

**Random** — uses `os.epoch("utc") + math.random()` seeded at boot from `os.epoch`. Not cryptographic, but fine for nonces and tokens.

### 5.3 Keys

Three kinds of secrets:

**Domain shared secret.** 32-byte hex string. One per registered domain. Issued by `NNA_REG` at install time. Stored on the domain server's filesystem (file: `/postroom/secret`, not in source). Used for HMAC and AES key derivation on all `POSTROOM/REG` traffic between that server and the registry.

**Staff terminal secret.** 32-byte hex. Configured manually at setup. Used for HMAC on `NNA_STAFF` ↔ `NNA_REG` traffic.

**Session secret.** 32-byte hex. Derived at user login: `HMAC(password_hash, "session:" .. login_nonce)`. Returned to the client as the session token; both client and server cache it. Used for `POSTROOM/USR` traffic. Expires after 7 in-game days of inactivity.

### 5.4 Signing

Every message has a `sig` field computed as:

```lua
sig = HMAC(key, canonical(message_without_sig))
```

`canonical` produces a deterministic serialization (sorted keys, escaped strings — same scheme as your airport code).

Receivers compute the expected signature and compare. Mismatches reject as `AUTH_FAILED`.

### 5.5 Encryption

Message bodies (the `body` field) are AES-128-CBC encrypted with a per-pair key derived from the shared secret:

```lua
encryption_key = HMAC(shared_secret, "encrypt:" .. message_id)
iv = first_16_bytes_of(HMAC(shared_secret, "iv:" .. message_id))
ciphertext = AES_CBC_encrypt(plaintext, encryption_key, iv)
```

This means each message has a unique key derived from its ID. Even with the same shared secret, no two ciphertexts share a key — limits exposure if any single message's plaintext is somehow recovered.

### 5.6 Replay protection

Every request carries a nonce. Servers maintain a rolling set of seen nonces (last 5 minutes). Replays are rejected with `AUTH_FAILED`.

The nonce set is bounded at 250 entries; when full, the oldest 50% are dropped. This is an in-memory structure — reboots reset it. Acceptable: an attacker would have to capture and replay within the reboot window.

### 5.7 Password storage

Passwords are hashed client-side before transmission:

```lua
client_hash = SHA256(domain .. ":" .. username .. ":" .. password)
```

The server stores `client_hash` directly (no further server-side salt — simplification). Login compares submitted `client_hash` to stored.

This means the server never sees plaintext passwords, and rainbow tables would have to be specific to `(domain, username)` pairs. Adequate for the threat model.

### 5.8 Why HMAC-SHA256 and not just FNV?

The previous airport code used FNV-1a 32-bit as a "signature" — that was honestly a tamper-detector, not a MAC. SHA256 is dramatically stronger and pure-Lua implementations are widely available and fast enough. There's no reason not to use it.

### 5.9 What's *not* protected

- **Metadata (`payload`).** Sender, recipient, subject, timestamps. Visible to anyone sniffing the network or to the registry. This matches real email — headers are clear-text in SMTP too.
- **Server compromise.** If a domain server is compromised, all its users' mail is exposed. This is the cost of letting users run their own servers. Use `@nmail` for privacy.
- **Brute force at scale.** A motivated attacker with no other constraints could try password attacks. The threat model assumes friends, not motivated attackers.

---

## 6. User Flows

Each flow is a sequence of screens or interactions, end to end.

### 6.1 Sign up for `@nmail` (or `@common`)

1. **Boot client.** User runs `pr` on a modemmed computer.
2. **Welcome screen.** "POSTROOM · NIO Mail" logo. Two options: "Sign in" or "Create account."
3. **Pick domain.** Client calls `list_public_domains` on `NNA_REG`. Shows the available list. User picks `@nmail`.
4. **Enter username.** Live-validated (3-16 chars, lowercase letters/digits, not reserved).
5. **Enter password (twice).** Min 6 chars. Hashed client-side.
6. **Submit.** Client calls `register` on `NMAIL_SRV`. On `USERNAME_TAKEN` it returns to step 4.
7. **Welcome.** Server creates account, sends a welcome message from `pm@nmail`. Client receives session token.
8. **Inbox.** Client displays inbox with the welcome message highlighted.

Total time: under a minute.

### 6.2 Sign in (returning user)

1. **Boot client.** If a valid cached session exists, skip to step 4.
2. **Pick "Sign in."** Or pick a remembered address.
3. **Enter address + password.** `username@domain` and password. Client calls `domain_status` on `NNA_REG` to find the server, then `login` on that server.
4. **Inbox.** On success, client lands at inbox.
5. **Forced password change.** If `must_change_password` flag is true, client immediately prompts for a new password before showing inbox.

### 6.3 Send a message

1. **From inbox, press `c`** (or click Compose).
2. **Compose screen.**
   - To: field. Autocomplete from local users (via `list_local_users`); accepts arbitrary cross-domain addresses.
   - Subject: field.
   - Body: multiline text area.
3. **Press `Ctrl+S` to send.**
4. **Validation.** Client checks: at least one valid-format address. Subject and body can be empty.
5. **Submit.** Client calls `send` on its home server.
6. **Server processing.**
   - Stores message, adds to sent folder.
   - For local recipients: delivers to their inbox.
   - For remote: calls `route_mail` on `NNA_REG`.
7. **Bounces (if any).** Failed recipients trigger bounce messages from `pm@<sender_domain>` into sender's inbox.
8. **Confirmation.** "Sent. (1 of 2 delivered, 1 bounced.)" if any bounces, else just "Sent." Returns to inbox.

### 6.4 Read a message

1. **From inbox**, arrow-key to a message, press Enter.
2. **Read view.** Switches to text mode. Header (From, To, Subject, Day) at top, body below, scrollable.
3. **Server marks read** on the `read_message` call.
4. **Actions.** `r` reply, `d` delete, `q` back to inbox.

### 6.5 Reply

1. **From read view, press `r`.**
2. **Compose with prefill.**
   - To: original sender.
   - Subject: `Re: <original>` (no double-prefix).
   - Body: empty, with quoted original below `--- On day N, alice@nmail wrote: ---`.
3. **Edit and send** — same as 6.3.

### 6.6 Register a new domain at the N.N.A. office

Prerequisites: applicant physically at the office. A staff member is on duty.

1. **Applicant approaches counter.** Verbally tells staff: "I'd like to register `@sundown`."
2. **Applicant presents fees.** Application fee (8ƒ) + registration fee (48ƒ) = 56ƒ in ingots, paid in person to staff.
3. **Staff at terminal.** Staff is logged in. From main menu, picks "New domain registration."
4. **Form.** Staff fills in:
   - Domain name: `sundown` (validated: 2-16 chars, lowercase, ASCII, not reserved, not taken).
   - Applicant name: `Bob` (player name).
   - Op username: `barkeep` (the op@<domain> username the owner wants).
   - Application fee paid: Y.
   - Registration fee paid: Y.
5. **Confirmation.** Terminal shows summary. Staff confirms with applicant verbally, then presses Confirm.
6. **Registry call.** Staff terminal calls `register_domain` on `NNA_REG`.
7. **Provisioning.** Registry:
   - Creates domain record with `status=PENDING_INSTALL`, `expires_day=now+48`.
   - Generates install token (16-char random).
   - Returns token and metadata to staff terminal.
8. **Floppy write.** Terminal prompts staff to insert blank floppy. Writes:
   ```
   { type="POSTROOM_INSTALL", domain="sundown",
     token="...", op_username="barkeep",
     registry_station="NNA_REG", issued_day=141, expires_day=148 }
   ```
   to file `disk/postroom_install`.
9. **Certificate print.** Terminal prints a paper certificate with domain, owner, issued day, token expiry, staff signature.
10. **Receipt print.** Terminal prints a receipt with all fees paid.
11. **Handover.** Staff hands floppy + certificate + receipt to applicant. Tells them: "Install within 7 days. Use a fresh modemmed computer."

### 6.7 Install a domain server

Prerequisites: applicant has the install floppy and a fresh modemmed computer with a disk drive.

1. **Insert floppy.** Computer auto-runs `disk/postroom_install_run` (the bootstrap), or owner runs `install` from the floppy manually.
2. **Install banner.** Screen displays:
   ```
   POSTROOM Domain Server Installer
   --------------------------------
   Domain: @sundown
   Installer token expires: day 148
   Continue? [Y/N]
   ```
3. **Connect to registry.** Installer pings `NNA_REG`. Confirms connectivity.
4. **Token consumption.** Sends `consume_install_token` with this computer's ID.
5. **Registry validates.** Token must exist, be `PENDING`, not expired. If valid:
   - Generates permanent shared secret.
   - Marks token consumed.
   - Updates domain: `status=ACTIVE`, `server_id=<this>`, `shared_secret=<new>`.
   - Returns secret + initial config + temporary `op` password.
6. **Local setup.** Installer:
   - Creates `/postroom/` directory.
   - Writes `/postroom/secret` (the shared secret, file-only).
   - Writes `/postroom/config` (domain name, registry station, install metadata).
   - Initializes `/postroom/state.txt` with op account, pm/abuse/noreply system accounts.
   - Writes `/startup.lua` to launch the server on boot.
7. **Display credentials.** Screen shows:
   ```
   INSTALLATION COMPLETE
   ---------------------
   Your op account: op@sundown
   Temporary password: TX7K-9PQR
   *** WRITE THIS DOWN ***

   You will be required to change this password on first login.

   Reboot to start the server.
   ```
8. **Reboot.** Server starts. From now on, it runs the mail server software on every boot, sends heartbeats, accepts connections.

### 6.8 Domain owner adds a user

1. **Op logs in.** From a PR client, login as `op@sundown`.
2. **First login: forced password change.** Op sets new password.
3. **Admin menu.** Op accounts see an extra "Domain Admin" sidebar option.
4. **Manage Users → Add User.**
   - Username: `bartender` (validated, unique-within-domain).
   - Initial password: auto-generated (e.g. `K7R9-X2MN`) or op-set.
5. **Submit.** Server calls `admin_create_user`.
6. **Welcome message.** Server creates account with `must_change_password=true`, sends welcome from `pm@sundown` with the temp password info.
7. **Op delivers credentials.** In person / DM / chat: "You're `bartender@sundown`, password is K7R9-X2MN, change on first login."

### 6.9 Renewal

**Auto-trigger:** registry's daily tick checks domains. Sends `notify_renewal` to domain servers when:
- 4 days before expiry: "Renewal due in 4 days."
- 2 days before: "Renewal due in 2 days."
- 0 days (expiry day): "Renewal overdue."
- During grace period (next 4 days): daily reminders.

Domain server forwards each notice to `op@<domain>`'s inbox as a system message.

**At the office:**

1. **Owner approaches counter** with renewal fee (12ƒ) in person.
2. **Staff lookup.** "Renew `@sundown` for Bob." Staff queries registry.
3. **Verify ownership.** Staff confirms player Bob is the registered owner. Trust by visual recognition.
4. **Process.** Staff selects domain, picks "Renew," confirms fee paid.
5. **Registry update.** Adds 48 days to `expires_day`. Logs renewal. Sends confirmation to op@<domain>.
6. **Receipt print.** Owner gets a renewal receipt.

### 6.10 Late renewal (grace and lapse)

| Day after expiry | Status | Behavior |
|---|---|---|
| 0–3 | ACTIVE (grace) | Server runs normally. Login shows "DOMAIN OVERDUE" warning. Daily renewal reminders. |
| 4–7 | SUSPENDED | New mail to/from domain bounces. Existing data preserved. Owner can pay to revive. |
| 8–29 | SUSPENDED (escalated) | Same as above. Final notice on day 14. |
| 30 | REVOKED | Domain returned to pool. Mail to it bounces with `UNKNOWN_DOMAIN`. Server receives `notify_revoked` and shuts down. |

Suspended domains can be revived by paying renewal at the office. Revoked domains require a new application.

### 6.11 Domain transfer

1. **Both parties at counter.** Old owner Bob, new owner Carol. Both physically present.
2. **Staff initiates.** "Transfer `@sundown` from Bob to Carol."
3. **Verbal verification.** Staff confirms identities and intent with both.
4. **Process.** Staff calls `transfer_domain` with new owner name and a new op password.
5. **Registry update.**
   - `owner_realname` changes from Bob to Carol.
   - Calls `admin_reset_password` on the domain server for the `op` account with the new password.
   - Logs the transfer.
6. **New password handover.** Staff prints the new op password slip, hands it to Carol. Bob is now locked out of `op@sundown`.
7. **Done.** Carol takes the slip, walks home, logs in, changes the password.

### 6.12 Domain revocation (manual)

Triggered by N.N.A. discretion (admin, not staff — or staff with admin flag).

1. **Admin at staff terminal.** Selects domain → "Revoke."
2. **Reason field.** Mandatory text field.
3. **Confirm.** Type `CONFIRM` to proceed.
4. **Process.** Registry sets `status=REVOKED`, sends `notify_revoked` to the domain server with reason. Domain server shuts down.
5. **Cooldown.** Domain name is held in `RECENTLY_REVOKED` state for 30 days before becoming available for re-registration. Prevents immediate re-grab.

### 6.13 Office closed

When no staff session is active on `NNA_STAFF`:

- Terminal displays: "OFFICE CLOSED · Please return when staff is on duty."
- All staff actions on the registry require an active session. Without one, the terminal cannot register, renew, transfer, or revoke.
- Routine operations (mail routing, heartbeat, automatic renewal warnings, lifecycle transitions) continue normally on the registry — no human needed.

### 6.14 Forgot password (user)

For `@nmail` and `@common`: not implemented in v1. Users who lose passwords lose accounts. (Future: email-recovery to a backup address.)

For private domains: user contacts their domain owner verbally; owner uses `admin_reset_password` to set a new temp password.

For `op@<domain>`: owner visits N.N.A. office. Staff verifies identity, calls a special staff-only `reset_op_password` action which resets the op password and emails the new one to... no, prints it on a slip, since email might not be reachable.

### 6.15 Forgot staff password

Admin-level only. Out of scope for the system; admin manually edits `staff_accounts` on `NNA_REG` to reset.

---

## 7. Visual Identity

### 7.1 Surfaces

The system has four distinct visual surfaces, each with its own palette and tone:

1. **N.N.A. Infrastructure** (`NNA_REG`, `NNA_STAFF`) — governmental, formal.
2. **Public Mail** (`NMAIL_SRV`, `COMMON_SRV`) — neutral utility.
3. **Private Domain Servers** — branded by their owners.
4. **PR Client** — chrome that reskins per server.

### 7.2 N.N.A. Infrastructure

**Vibe:** mid-century postal authority. Trustworthy, formal, slightly dry. Like a regional telecom or a national post office.

**Palette (Mode 1, 16 colors — assigned to slots):**

| Slot | Hex | Use |
|---|---|---|
| 0 (background) | `#1a2332` | screen background, deep slate blue |
| 1 (primary) | `#e8e0c8` | body text, pale cream |
| 2 (accent) | `#c9a04a` | headings, logo, muted gold |
| 3 (secondary) | `#7a8a9c` | hints, timestamps, blue-gray |
| 4 (success) | `#4a8a4a` | confirmations, green |
| 5 (warning) | `#d8a03a` | overdue, amber |
| 6 (error) | `#a04a3a` | revocation, faded brick |
| 7 (highlight) | `#3a5a78` | selection, blue |

**Logo:** "N.N.A." in 7-pixel block letters, gold on slate. Optional small icon: a stylized envelope inside a triangle, or a postal horn.

**Tone of voice in mail and notices:**

- Welcome to a domain owner: "Dear Operator, welcome to the National Network Authority. Your domain `@sundown` was registered on Day 141. Please find attached your operating reference materials."
- Renewal reminder: "Notice of Renewal. Your domain `@sundown` is due for biannual renewal on Day 189. Please attend the N.N.A. office at your earliest convenience to remit the renewal fee of 12ƒ."
- Revocation notice: "Notice of Revocation. Pursuant to operations standards, your domain `@sundown` has been revoked effective Day 192. Reason: [reason]. Appeals may be addressed to the office in person."

Slightly archaic, formal, but warm at the edges.

### 7.3 Public Mail (`@nmail` and `@common`)

**Vibe:** neutral, utility, accessible. The "boring email service" of this world.

**`@nmail` palette:**

| Slot | Hex | Use |
|---|---|---|
| 0 (background) | `#0e1a2a` | dark navy |
| 1 (primary) | `#f0f2f5` | white-ish |
| 2 (accent) | `#4a8acc` | cool blue |
| 3 (secondary) | `#6878a0` | muted blue-gray |
| 4 (unread dot) | `#5aaeff` | bright cyan |

**`@common` palette:**

| Slot | Hex | Use |
|---|---|---|
| 0 | `#1f1d1a` | warm gray |
| 1 | `#e8e2d4` | warm white |
| 2 | `#3aa098` | muted teal |
| 3 | `#7a7264` | warm secondary |
| 4 | `#5cd0c4` | unread teal |

**Tone:** brief, neutral, helpful. "Welcome to NIO Mail. You're now signed up as alice@nmail. Send your first message any time. Need help? Contact pm@nna."

### 7.4 Private Domain Servers

**Vibe:** entirely owner-controlled. Each owner sets their own palette via `admin_set_branding`.

The branding object lets the owner pick:

- `display_name` — what shows in the title bar.
- `theme_palette` — 8 hex colors mapped to slots 0-7.
- `sign_off` — appended to the welcome message and visible in profile.

**Default starter palette** (for owners who don't customize): same as `@common`.

**Example for `@sundown` (a bar):**
- Background: dim warm orange (sunset)
- Primary: cream
- Accent: amber
- "WELCOME TO THE SUNDOWN CLUB · Open from dusk till dawn"

**Example for `@wbia` (the airport):**
- Background: deep warm brown
- Primary: lantern amber
- Accent: pale gold
- "WBIA OPERATIONS CENTER · NIO AirLounge"

### 7.5 PR Client (chrome)

The client is one program; it inherits the connected server's palette via `domain_meta.branding`.

#### Boot screen (Mode 2 graphics)

Displays at app launch.

```
   ┌──────────────────────────────────────┐
   │                                      │
   │           [POSTROOM logo]            │
   │                                      │
   │         POSTROOM · NIO Mail          │
   │                                      │
   │   Connecting to network...     [OK]  │
   │   Resolving registry...        [OK]  │
   │                                      │
   └──────────────────────────────────────┘
```

Logo fades in pixel-by-pixel using `term.drawPixels`. Status lines tick on with a subtle chime.

#### Login screen (Mode 1)

```
   ┌─────────────────────────────────────────────────┐
   │ POSTROOM                                  v1.0  │ ← title bar
   ├─────────────────────────────────────────────────┤
   │                                                 │
   │              ┌───────────────────────┐          │
   │              │     SIGN IN           │          │
   │              │                       │          │
   │              │ Address: [          ] │          │
   │              │ Password:[          ] │          │
   │              │                       │          │
   │              │  [Sign In]  [Create]  │          │
   │              └───────────────────────┘          │
   │                                                 │
   ├─────────────────────────────────────────────────┤
   │ [Tab] switch field  [Enter] submit  [c] new acct│
   └─────────────────────────────────────────────────┘
```

#### Inbox view (Mode 1) — the main view

```
┌──────────────────────────────────────────────────────────┐
│ POSTROOM · @nmail · alice              4 unread · ƒ ━━━ │ ← title bar
├─────────┬────────────────────────────────────────────────┤
│ INBOX  4│ ● From Bob          Hey, you free for...   d141│
│ Sent    │ ○ From pm@nna       Renewal reminder       d140│ ← list
│ Trash   │ ○ From Alice        Re: groceries          d139│
│         │ ○ From Carol        Lunch tomorrow?        d139│
│ Compose │ ● From Bob          Pictures from the trip d138│
│         │ ● From pm@nmail     Welcome!               d135│
│ ─ ADMIN │                                                │
│ Users   │                                                │
│ Brand   │                                                │
├─────────┴────────────────────────────────────────────────┤
│ [↑↓] navigate  [Enter] open  [c] compose  [d] delete  [q]│ ← hint bar
└──────────────────────────────────────────────────────────┘
```

- Filled circles (`●`) = unread.
- Sidebar shows folder counts. Admin section only visible for op accounts.
- Selected row highlighted.
- Title bar shows server brand, account, unread count.

#### Read view (text mode)

```
┌──────────────────────────────────────────────────────────┐
│ FROM:    bob@sundown                                     │
│ TO:      alice@nmail                                     │
│ SUBJECT: Hey, you free for drinks?                       │
│ DAY:     141                                             │
├──────────────────────────────────────────────────────────┤
│                                                          │
│ Hi Alice,                                                │
│                                                          │
│ I'll be at the Sundown Club tonight after sundown.       │
│ Wanted to know if you'd join us. Carol's coming too.     │
│                                                          │
│ — Bob                                                    │
│                                                          │
│                                                          │
├──────────────────────────────────────────────────────────┤
│ [r] reply  [d] delete  [↑↓] scroll  [q] back             │
└──────────────────────────────────────────────────────────┘
```

#### Compose view (text mode)

```
┌──────────────────────────────────────────────────────────┐
│ COMPOSE                                                  │
├──────────────────────────────────────────────────────────┤
│ TO:      bob@sundown                                     │
│ SUBJECT: Re: Hey, you free for drinks?                   │
├──────────────────────────────────────────────────────────┤
│                                                          │
│ I'll be there. See you at 8.                             │
│                                                          │
│ — Alice                                                  │
│                                                          │
│ --- On day 141, bob@sundown wrote: ---                   │
│ > Hi Alice,                                              │
│ > I'll be at the Sundown Club tonight...                 │
│                                                          │
├──────────────────────────────────────────────────────────┤
│ [Ctrl+S] send  [Ctrl+X] cancel  [Tab] next field         │
└──────────────────────────────────────────────────────────┘
```

### 7.6 Staff terminal (NNA_STAFF)

#### Boot / login

```
┌──────────────────────────────────────────────────────────┐
│                                                          │
│           NATIONAL NETWORK AUTHORITY                     │
│           ─────────────────────────                      │
│                                                          │
│           Office Operations Terminal                     │
│                                                          │
│           Staff login required                           │
│                                                          │
│           Username: [          ]                         │
│           Password: [          ]                         │
│                                                          │
│           ── Office hours when staffed ──                │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

#### Main menu

```
┌──────────────────────────────────────────────────────────┐
│ N.N.A. OFFICE TERMINAL · Staff: alice          Day 141   │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  1. New domain registration                              │
│  2. Process renewal                                      │
│  3. Domain transfer                                      │
│  4. Look up domain                                       │
│  5. Browse all domains                                   │
│  6. Revoke domain (admin)                                │
│  7. View today's transactions                            │
│  8. Audit log                                            │
│                                                          │
│  0. End shift (logout)                                   │
│                                                          │
├──────────────────────────────────────────────────────────┤
│ Active sessions: 1   Pending today: 0                    │
└──────────────────────────────────────────────────────────┘
```

#### Office closed screen (no staff session)

```
┌──────────────────────────────────────────────────────────┐
│                                                          │
│                                                          │
│                                                          │
│                  N.N.A. OFFICE                           │
│                                                          │
│                  ─── CLOSED ───                          │
│                                                          │
│      Please return when staff is on duty.                │
│                                                          │
│                                                          │
│      Domain registrations, renewals, and transfers       │
│           require an attendant on duty.                  │
│                                                          │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### 7.7 Tone of voice (system mail)

System messages are signed by `pm@<domain>` and have a recognizable structure:

```
FROM:    pm@nna
TO:      op@sundown
SUBJECT: Notice of Renewal — @sundown

Dear Operator,

This notice serves to advise you that your domain @sundown
is approaching its biannual renewal date.

  Domain:        @sundown
  Renewal due:   Day 189 (in 4 days)
  Renewal fee:   12ƒ

Please attend the N.N.A. office at your earliest
convenience to remit the renewal fee in person.

Failure to renew within the grace period (4 days
following expiry) will result in suspension of your
domain server. Continued non-payment will result
in revocation on day 218.

  ─── National Network Authority ───
       Issued: Day 185
       Form NNA-R-3
```

Form numbers, formal salutations, slightly bureaucratic. Not threatening — informational, civic.

---

## 8. Naming and Identifiers

### 8.1 Computer station names

| Computer | Station name |
|---|---|
| Registry | `NNA_REG` |
| Staff terminal | `NNA_STAFF` |
| @nmail server | `NMAIL_SRV` |
| @common server | `COMMON_SRV` |
| Generic domain server | `<UPPERDOMAIN>_SRV` (e.g. `SUNDOWN_SRV`) |
| Mail clients | `CLIENT:<computer_id>` |

### 8.2 Protocol names

- Network protocol: `POSTROOM_NET` (rednet protocol string)
- Sub-protocols within messages:
  - `POSTROOM/REG` — server-to-registry
  - `POSTROOM/USR` — client-to-server

### 8.3 App and product names

- The system: **Postroom**
- The client app: **PR** (filename `pr` or `pr.lua`)
- The mail brand: **NIO Mail** (consumer-facing umbrella)
- The authority: **N.N.A.** (National Network Authority)
- The public mail brands: **National Mail** (`@nmail`), **Common** (`@common`)

### 8.4 Domain name rules

- 2-16 characters
- Lowercase ASCII letters and digits only
- No hyphens, underscores, or punctuation in v1
- Not in `reserved_names`
- Case-insensitive at lookup; stored lowercase

### 8.5 Username rules

- 2-16 characters
- Lowercase ASCII letters and digits, underscores allowed
- Not in `op`, `pm`, `abuse`, `noreply`
- Case-insensitive at lookup; stored lowercase
- Display name is just the username; no separate display name in v1

### 8.6 Reserved names (registry)

```
gov · nna · nmail · common
nta · nga · nhsa · nfa
nra · nwa · nea · nba · nja · nma · nca
mil · court · treasury
admin · system · root · public · noreply
op · pm · abuse · postmaster
```

Of these, **only `nna`, `nta`, `nga`, `gov`, `nmail`, `common` are intended to be issued in v1.** The rest are reserved for future use.

### 8.7 Reserved local-parts (every domain)

Every domain has these system local-parts that cannot be issued to users:

- `op` — domain owner (auto-created with the domain)
- `pm` — postmaster (system-only sender; auto-created)
- `abuse` — abuse reports (auto-created, inert in v1)
- `noreply` — non-replyable system mail (auto-created, system-only)

### 8.8 ID formats

- Domain ID: the domain name itself (e.g., `sundown`).
- Message ID on each server: `MSG-NNNN` (zero-padded sequence per server).
- Install token: 16 chars from base32-friendly alphabet `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, formatted `XXXX-XXXX-XXXX-XXXX`.
- Session token: 32-byte hex.
- Staff session token: 32-byte hex, separate from user sessions.

---

## 9. Pricing and Economics

All prices are in `ƒ` (fluorin), the same currency as the airport. Display in computers as `f`.

### 9.1 Domain fees

| Fee | Amount | Paid when | Note |
|---|---|---|---|
| Application fee | 8ƒ | At registration | Non-refundable. Covers staff processing. |
| Initial registration fee | 48ƒ | At registration | Covers first 2 seasons of operation. |
| Renewal fee | 12ƒ | Every 2 seasons | Bi-seasonal (every 48 days) renewal cost. |

Total to register a new domain: **56ƒ** (8 + 48).
Per-season cost: roughly **6ƒ** (12 / 2).

### 9.2 N.N.A. revenue split

Of every fee collected, 3ƒ is logged as **N.N.A. share** in the billing log. (Bookkeeping only — there's no actual revenue redistribution; this just makes the system feel real and gives you data for "how much has the N.N.A. earned this season" reports.)

### 9.3 Account fees

- `@nmail` and `@common` accounts: free.
- Private domain accounts: free at the domain server level. The domain owner may charge their own users out-of-band; that's their business.

### 9.4 Other costs

- Office visit: free.
- Domain transfer: 8ƒ (treated as a new application fee; covers paperwork).
- Reinstatement after revocation: requires full new registration (8 + 48 = 56ƒ).
- Late renewal during grace period: still 12ƒ, no penalty.
- Late renewal during suspension: 12ƒ + 8ƒ reinstatement fee = 20ƒ.

### 9.5 Pricing in context

For comparison with the airport's economy:

- An airpass is 10ƒ per season.
- Parking is 3ƒ/day.
- Fuel-N is 12ƒ/stack.

So a domain registration (56ƒ) costs roughly the same as a few weeks of aircraft parking. A renewal (12ƒ) is comparable to a season's airpass plus a small surcharge. Meaningful but not blocking — a player who runs a small business can absolutely afford to maintain a domain.

---

## 10. Lifecycle and Edge Cases

### 10.1 Daily tick on registry

Every in-game day at midnight, `NNA_REG` runs a maintenance pass:

1. **Expire install tokens.** Tokens past `expires_day` with `status=PENDING` are marked `EXPIRED`.
2. **Renewal warnings.** For domains with `expires_day - now ∈ {4, 2, 0}` and active status, send `notify_renewal` to the domain server.
3. **Suspension transitions.** Domains where `now - expires_day ∈ [4, 7]` and status is `ACTIVE`: set to `SUSPENDED`, send `notify_suspended`.
4. **Revocation transitions.** Domains where `now - expires_day >= 30` and status is `SUSPENDED`: set to `REVOKED`, send `notify_revoked`.
5. **Cleanup.** Revoked domains older than 60 days are purged from the registry (frees the name).
6. **Heartbeat sweep.** Domains with no heartbeat for 24+ hours: send a warning to op via system mail.

The tick should be idempotent — running it twice produces the same result.

### 10.2 Server restart

When a domain server restarts:

1. Load state from disk.
2. Read shared secret from `/postroom/secret`.
3. Open modem, host on `POSTROOM_NET` as the domain station name.
4. Send a `heartbeat` to `NNA_REG` immediately to establish online status.
5. Begin accepting client connections and routed mail.

If the registry doesn't respond on startup, the server can still serve local users (login, send to same-domain) but can't deliver cross-domain mail. Bounce immediately on attempts.

If the registry says the server's domain is `REVOKED`, the server should refuse to start serving and display a "domain revoked" notice.

### 10.3 Registry restart

When `NNA_REG` restarts:

1. Load state from disk.
2. Open modem, host as `NNA_REG`.
3. Run a daily-tick pass if more than 24 hours have passed since the last tick (catch-up).
4. Resume accepting requests.

Domain servers that pinged during the downtime would have had timeouts; they'll re-attempt heartbeats on their next cycle.

### 10.4 Client restart

Client checks for a cached session on startup. If valid, attempts to use it. On `AUTH_FAILED` (e.g. session expired), discards the cache and shows the login screen.

### 10.5 Network partition

If a domain server can reach clients but not the registry: same-domain mail works, cross-domain bounces. The server keeps trying heartbeats; once registry is reachable again, heartbeats resume.

If the registry can reach `@nmail` but not `@sundown`: routing to `@sundown` fails (DOMAIN_OFFLINE bounces), routing to `@nmail` succeeds.

### 10.6 Edge cases worth handling explicitly

**Sending to a nonexistent local user.** Server returns `UNKNOWN_RECIPIENT` per-recipient. No bounce needed — the sender's home server itself rejected.

**Sending to a nonexistent remote user.** Home server forwards to registry, registry forwards to destination, destination returns `UNKNOWN_RECIPIENT`, home server creates a bounce.

**Sending to a nonexistent domain.** Home server forwards to registry, registry returns `UNKNOWN_DOMAIN`, home server bounces.

**Sending to a suspended/revoked domain.** Same as offline: bounces.

**Self-send.** Allowed. Lands in own inbox (and own sent folder — same message reference).

**Empty recipients.** Rejected client-side and server-side as `INVALID_REQUEST`.

**Long body.** Capped at 4000 chars. Beyond, rejected.

**Long subject.** Capped at 200 chars. Beyond, truncated.

**Username collision during registration.** Returns `USERNAME_TAKEN`. Client retries with a different name.

**Domain collision during registration.** Same: `USERNAME_TAKEN` (technically `DOMAIN_TAKEN`).

**Two simultaneous installs from the same token.** Should not happen (token is single-use), but if a race occurs: registry is single-threaded in its event loop; first wins, second gets `INVALID_TOKEN`.

**Deleting an op account.** Forbidden. Cannot delete. Returns `INSUFFICIENT_PERMISSIONS`.

**Deleting a system account (pm/abuse/noreply).** Forbidden.

**Op changing own username.** Not supported in v1. Username changes require a domain transfer.

**Mail to op@<own_domain> from inside.** Works normally. Op's inbox is just a regular inbox.

**Mailing across to a domain that's currently offline but recovers within the same "session."** Sender already bounced. Resending after recovery works.

### 10.7 Capacity limits

| Limit | Value | Behavior on hit |
|---|---|---|
| Messages per user | 500 | New mail rejected with `MAILBOX_FULL` (warning to sender) |
| Sent folder | 500 | Oldest auto-deleted |
| Trash retention | 14 days | Auto-purged |
| Audit log on registry | 1000 entries | Oldest 50% purged when exceeded |
| Audit log on mail server | 500 entries | Oldest 50% purged when exceeded |
| Body length | 4000 chars | Rejected if exceeded |
| Subject length | 200 chars | Truncated |
| Address list (To:) | 16 recipients | Rejected if exceeded |
| Domains in registry | 256 | Soft cap; warning to admin |
| Concurrent staff sessions | 1 | New login boots prior session |
| Concurrent user sessions per account | 3 | Oldest session evicted on 4th |

---

## 11. Build Order

Build the system in this order. Each phase is independently testable and unblocks the next.

### Phase 1 — Foundation (Registry + One Public Server)

**Goal:** Have a working registry and one mail server that can register and authenticate users locally.

1. Build crypto utilities: SHA256, HMAC, AES-128-CBC, canonical serialization, nonce/replay. Test in isolation.
2. Build `NNA_REG`: state model, request handler skeleton, action stubs for `domain_status`, `list_public_domains`, daily tick (no-op for now).
3. Build `NMAIL_SRV`: state model, request handler, actions for `register`, `login`, `logout`, `account_info`. No mail features yet. Pre-register `@nmail` in the registry manually for now.
4. Build minimal PR client: text-mode boot, login/register flow, "you are logged in as alice@nmail" placeholder screen.

**Test:** Boot all three computers. Create alice@nmail. Log out. Log back in.

### Phase 2 — Local Mail (Same Domain Only)

**Goal:** Send and receive mail within `@nmail`.

5. Add `send`, `list_inbox`, `read_message`, `delete_message` to `NMAIL_SRV` for local-only delivery.
6. Add compose, inbox display, read screens to PR client.
7. Add `pm@nmail` system account; auto-send welcome message on registration.

**Test:** alice@nmail sends to bob@nmail. Both check inboxes. alice deletes a message.

### Phase 3 — Federation (Cross-Domain Mail)

**Goal:** Mail can flow between `@nmail` and a second domain.

8. Build `COMMON_SRV` (clone of `NMAIL_SRV`, different config). Pre-register `@common` in registry.
9. Add `route_mail` to `NNA_REG` and `deliver_mail` to mail servers.
10. Update `send` on mail servers to route cross-domain.
11. Implement bounce semantics: failed delivery creates a bounce in sender's inbox.

**Test:** alice@nmail mails bob@common. bob receives. bob replies. Disconnect `COMMON_SRV`. alice tries to mail bob — receives a bounce.

### Phase 4 — Private Domain Servers

**Goal:** Domain registration, install token, private server bootstrap.

12. Build `register_domain` action on `NNA_REG`. Issue install tokens. Persist them.
13. Build `consume_install_token`. Generate shared secrets. Activate domains.
14. Write the install script (`install.lua` for the floppy).
15. Build a generic domain server program (one codebase that runs `@sundown` or any other domain based on its config).

**Test:** Manually trigger `register_domain` (no staff terminal yet). Write the install token to a floppy by hand. Bootstrap a `@sundown` server. Send mail across all three domains.

### Phase 5 — Staff Terminal

**Goal:** N.N.A. office is operational.

16. Build `NNA_STAFF`: staff login, main menu.
17. Implement domain registration flow with floppy writer and certificate printer.
18. Implement domain lookup, renewal, revocation.
19. Implement transfer and audit log views.
20. Add the office-closed screen when no staff session active.

**Test:** Staff logs in, processes a registration end-to-end. Applicant takes the floppy, installs, server comes online. Staff later processes a renewal. Staff revokes a domain — server shuts down.

### Phase 6 — Lifecycle Automation

**Goal:** Renewals, suspensions, revocations happen automatically.

21. Implement daily tick on registry.
22. Implement renewal warnings via `notify_renewal`.
23. Implement suspension and revocation transitions.
24. Implement cleanup of expired install tokens and stale revoked domains.

**Test:** Manually advance the registry's day counter. Verify warnings, suspensions, revocations trigger correctly.

### Phase 7 — Domain Admin Features

**Goal:** Domain owners can manage their domain.

25. Add `admin_create_user`, `admin_delete_user`, `admin_reset_password`, `admin_view_user_inbox`, `admin_view_message`, `admin_set_branding`, `admin_domain_stats` to mail server.
26. Add admin sidebar to PR client (visible only for op accounts).
27. Implement first-login forced password change.

**Test:** op@sundown logs in, creates a user, views that user's inbox, changes branding, sees stats.

### Phase 8 — Visual Polish

**Goal:** The system looks the part.

28. Implement Mode 2 boot screens for all server types.
29. Implement Mode 1 chrome for the PR client (title bar, sidebar, list view).
30. Implement per-server palette swapping based on connected server's branding.
31. Implement system mail templates (welcomes, renewals, bounces, revocations) with proper tone.
32. Add sound effects: chime on new mail, click on send, soft tick on selection.

**Test:** Boot the system. Take screenshots. Compare against the design document. Adjust palettes.

### Phase 9 — Hardening

**Goal:** The system is robust enough to leave running.

33. Stress test: 10 users, 100 messages, 5 domains, simulated outages.
34. Implement capacity limits (mailbox full, audit log rotation).
35. Implement client-side error handling for every error code.
36. Write the "Postroom Operator's Handbook" (a paper book with usage instructions for users) and the "N.N.A. Staff Manual" (for staff terminal operators).
37. Final review against this design document.

### Phase 10 — Launch

38. Deploy. Set initial domains. Add yourself as staff. Open the office.
39. Add `@wbia` (the airport's domain) as a private domain.
40. Walk friends through onboarding.

---

## 12. Future Considerations

These are intentionally out of scope for v1, listed for future planning:

### 12.1 Likely v2 features

- **Drafts.** Save unfinished mail.
- **Threading by subject.** Group mail with the same `Re:` chain visually.
- **Reply-all.** Reply to all recipients.
- **Read receipts.** Sender can request notification when read.
- **Address book.** Per-user contacts.
- **Display names.** Optional human-readable names attached to addresses.

### 12.2 Possible v3 features

- **Pocket client.** Run on pocket computers, with simplified UI. Test graphics-mode stability first.
- **Attachments.** Reference files in messages, with size limits.
- **Domain deputies.** Multiple admin-flagged users per domain.
- **Auto-responders.** Out-of-office replies.
- **Federation across servers.** Multiple registries that gossip.

### 12.3 Things to never do

- **Push notifications via redstone.** Tempting but feels overengineered.
- **Real public-key cryptography.** Not necessary; HMAC + AES is enough.
- **Multi-server replication of the registry.** Complexity explosion. One registry is fine.
- **Voice messages, video messages.** This is a text mail system. Stay focused.
- **Cryptocurrency integration.** No.

### 12.4 Open questions for later

- Should there be a "block sender" feature for users who get harassed?
- Should domain owners be able to set a per-domain "tagline" that appears on outbound mail?
- Should there be a special "bulletin board" account type that broadcasts to all subscribers?
- Should `pm@nna` accept incoming user mail (for support) or be one-way?

---

## Appendix A: Quick Reference

### A.1 Computer cheatsheet

| Computer | Boots | Talks to | Stores |
|---|---|---|---|
| `NNA_REG` | always | everyone | registry, install tokens, staff, audit, billing |
| `NNA_STAFF` | always (closed if no staff) | `NNA_REG` | recent staff sessions only |
| `NMAIL_SRV` | always | `NNA_REG`, clients | `@nmail` accounts and mail |
| `COMMON_SRV` | always | `NNA_REG`, clients | `@common` accounts and mail |
| `<DOMAIN>_SRV` | always | `NNA_REG`, clients | one domain's accounts and mail |
| Client | on demand | one mail server at a time | session token only |

### A.2 Address parsing

```lua
function parseAddress(s)
  local user, domain = s:match("^([%w_]+)@([%w]+)$")
  if not user or not domain then return nil end
  return user:lower(), domain:lower()
end
```

### A.3 Fee table

```
Application fee:             8ƒ
Initial registration:       48ƒ
Renewal (every 2 seasons):  12ƒ
Transfer:                    8ƒ
Reinstatement after revoke: 56ƒ (full re-registration)
N.N.A. share per fee:        3ƒ (bookkeeping)
```

### A.4 Lifecycle timeline

```
Day 141: Domain registered, expires day 189.
Day 185: First renewal warning (4 days out).
Day 187: Second warning (2 days out).
Day 189: Expiry. Status: ACTIVE (grace).
Day 190-192: Daily warnings during grace.
Day 193: SUSPENDED. Mail bounces.
Day 207: Final notice.
Day 218: Status: REVOKED. Server shuts down.
Day 248: Domain name returns to pool.
```

### A.5 Reserved names quick list

**Issued domains in v1:** `gov`, `nna`, `nta`, `nga`, `nmail`, `common`.

**Reserved but not yet issued:** `nhsa`, `nfa`, `nra`, `nwa`, `nea`, `nba`, `nja`, `nma`, `nca`, `mil`, `court`, `treasury`.

**Always reserved on every domain:** `op`, `pm`, `abuse`, `noreply`, `postmaster`, `admin`, `system`, `root`.

---

## End of document

This document is the source of truth for Postroom v1. Implementation may begin once this design is signed off.

*Issued by the National Network Authority · NIO Office of Operations · Drafted for first deployment.*
