# Postroom

A federated email-style messaging system implemented in ComputerCraft (CC: Tweaked).

> **NIO Mail · operated by the National Network Authority**

Postroom is a multi-server mail system for an in-game Minecraft world. It models real telecom infrastructure: a central authority (the N.N.A.) that issues domain namespaces, a public mail service (`@nmail`, `@common`) for unaffiliated users, and privately-operated domain servers for businesses and organizations. Mail is signed with HMAC-SHA256 and bodies encrypted with AES-128-CBC, all in pure Lua.

## Status

🚧 **In active development.** See [`STATE.md`](./STATE.md) for current implementation progress.

## Documentation

- [`STATE.md`](./STATE.md) — current build state, what's done, what's pending, known issues
- [`DESIGN.md`](./DESIGN.md) — full system design specification
- [`HANDOFF_PROMPT.md`](./HANDOFF_PROMPT.md) — orientation message for Claude Code or future maintainers

## What this is, in one paragraph

The N.N.A. (National Network Authority) is a player-staffed government office. Players walk in to register a domain — say `@sundown` for their bar — pay a fee, and walk out with a paper certificate and an install floppy. They take the floppy home, set up a modemmed computer, and run the installer. The new computer authenticates to the N.N.A. registry, gets a permanent shared secret, and becomes the mail server for `@sundown`. From that point on, players with `@sundown` accounts can mail anyone else on the network — `@nmail`, `@common`, `@wbia`, etc. Mail is routed through the registry, signed end-to-end, and bounces immediately if a domain server is offline. The owner of `@sundown` can read all `@sundown` mail (clearly disclosed at signup); users who want privacy use `@nmail` or `@common`. Domains have bi-seasonal renewal fees and lapse if unpaid, with a grace period and revocation lifecycle.

## Architecture summary

Five computer types make up a working deployment:

| Computer | Role | Owner |
|---|---|---|
| `NNA_REG` | Registry, routing, audit | N.N.A. (you) |
| `NNA_STAFF` | Counter terminal, processes applications | N.N.A. (you) |
| `NMAIL_SRV` | `@nmail` public mail server | N.N.A. (you) |
| `COMMON_SRV` | `@common` public mail server | N.N.A. (you) |
| `<DOMAIN>_SRV` | One private domain server per registered domain | The domain owner |

Plus client computers running the **PR client** (the mail app).

Cryptography is HMAC-SHA256 for authentication and AES-128-CBC for body encryption. Both are implemented in pure Lua and verified against published test vectors.

## Project layout (target)

```
postroom/
├── README.md
├── DESIGN.md
├── STATE.md
├── HANDOFF_PROMPT.md
├── src/
│   ├── lib/
│   │   ├── crypto.lua       ✓ done
│   │   ├── wire.lua         ✓ done
│   │   └── common.lua       ✓ done
│   ├── nna_reg.lua          ✗ pending (batch 2)
│   ├── nmail_srv.lua        ✗ pending (batch 3)
│   ├── common_srv.lua       ✗ pending (batch 3)
│   ├── pr_client.lua        ✗ pending (batch 4)
│   ├── domain_srv.lua       ✗ pending (batch 5)
│   ├── install_disk.lua     ✗ pending (batch 5)
│   └── nna_staff.lua        ✗ pending (batch 6)
├── tests/
│   ├── crypto_test.lua      ✓ done — 31/31 passing
│   ├── wire_test.lua        ✓ done — 50/50 passing
│   └── common_test.lua      ✓ done — 52/52 passing
└── installers/              ✗ pending (final phase)
    ├── install_registry.lua
    ├── install_nmail.lua
    ├── install_common.lua
    ├── install_domain.lua
    ├── install_client.lua
    └── install_staff.lua
```

## Conventions

- **Lua style:** plain procedural Lua, no class systems, no metatables for inheritance. Match the style in the existing libraries.
- **Persistence:** atomic writes via `tmp + fs.move`. State on disk as `textutils.serialize`d tables.
- **Auth:** every cross-computer message is signed (HMAC) and includes a nonce (replay-protected). Bodies that need confidentiality are AES-encrypted.
- **Errors:** uppercase string codes (`AUTH_FAILED`, `UNKNOWN_DOMAIN`, `DOMAIN_OFFLINE`, etc.). See `DESIGN.md` § 3.5.
- **No shortcuts on crypto:** SHA-256 must verify FIPS 180-4 vectors, HMAC must verify RFC 4231, AES must verify FIPS 197. Tests in `tests/` validate this.

## License

To be decided by the project owner.
