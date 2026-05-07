# Postroom

A federated email-style messaging system implemented in ComputerCraft (CC: Tweaked).

> **NIO Mail · operated by the National Network Authority**

Postroom is a multi-server mail system for an in-game Minecraft world. It models real telecom infrastructure: a central authority (the N.N.A.) that issues domain namespaces, a public mail service (`@nmail`, `@common`) for unaffiliated users, and privately-operated domain servers for businesses and organizations. Mail is signed with HMAC-SHA256 and bodies encrypted with AES-128-CBC, all in pure Lua.

## Status

✅ **v1 feature-complete.** All six batches plus the pastebin installer phase are done. 314/314 tests passing across nine suites. End-to-end testing in CraftOS-PC and final pastebin uploads are the remaining steps. See [`STATE.md`](./STATE.md) for the full per-component status.

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

## Deploying

1. **Run the registry first.** Pastebin upload `installers/install_registry.lua`, then on a fresh CC computer with a wireless modem: `pastebin get <id> install && install && reboot`. On the next boot the registry prints two things: a 64-character staff terminal secret (you'll paste this into the staff terminal in step 2), and the bootstrap admin credentials (`admin / changeme`).
2. **Set up the staff terminal.** Pastebin `installers/install_staff.lua`. On a CC computer with a wireless modem, disk drive, and printer: `pastebin get <id> install && install && reboot`. On first boot the terminal asks for the staff secret you wrote down.
3. **Register `@nmail` and `@common`** at the staff terminal (operator name = "N.N.A.", op_username = "op"). Take each install floppy to its public-server CC computer.
4. **Run the public server installers.** `pastebin get <id> install && install` for `install_nmail.lua` / `install_common.lua` — these include the install ceremony inline.
5. **For each private domain customer**, register them at the staff terminal, hand them the floppy, and have them run `install_domain.lua` on their own CC computer.
6. **Players install the client** with `install_client.lua` and run `pr` to launch it.

## Project layout

```
postroom/
├── README.md
├── DESIGN.md
├── STATE.md
├── HANDOFF_PROMPT.md
├── src/
│   ├── lib/
│   │   ├── crypto.lua          SHA-256 / HMAC / AES-128-CBC / passwords
│   │   ├── wire.lua            canonical serialization + signing + replay
│   │   ├── common.lua          constants, validators, persistence, UI
│   │   └── mail_server.lua     shared core for all three mail-server roles
│   ├── nna_reg.lua             registry + lifecycle tick
│   ├── nmail_srv.lua           @nmail public server (thin wrapper)
│   ├── common_srv.lua          @common public server (thin wrapper)
│   ├── domain_srv.lua          generic private domain server
│   ├── install_disk.lua        floppy bootstrap (consume install token)
│   ├── pr_client.lua           PR mail client (text-mode UI)
│   └── nna_staff.lua           N.N.A. office counter terminal
├── tests/                      314/314 passing
│   ├── crypto_test.lua            31  FIPS / RFC vectors
│   ├── wire_test.lua              50  serialization, signing, replay
│   ├── common_test.lua            52  validators, persistence, UI
│   ├── nna_reg_test.lua           67  dispatch, handlers, daily tick
│   ├── mail_server_test.lua       60  USR + REG action coverage
│   ├── pr_client_test.lua          6  smoke
│   ├── install_test.lua           29  installer pure helpers
│   ├── nna_staff_test.lua          7  smoke
│   └── installers_test.lua        12  syntax + URL checks for pastebins
└── installers/
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
