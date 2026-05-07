# Handoff Prompt for Claude Code

## How to use this file

Copy the text below the `---` line into a new Claude Code session. Have your repo open as the working directory. Claude Code will read the existing files and pick up where the previous session left off.

If you want to lead with a specific request (e.g. "first, set up git and push what we have"), add that at the bottom before sending.

---

# CONTEXT

I'm continuing a project called **Postroom**, a federated email-style messaging system written in pure Lua for ComputerCraft (CC: Tweaked) in Minecraft. The design and the foundation libraries were built in a previous Claude conversation. You're picking up where that conversation ended.

**Read these three files first, in order, before doing anything else:**

1. `README.md` — high-level orientation
2. `STATE.md` — exactly where we are right now, what's done, what's pending, conventions, known issues
3. `DESIGN.md` — the full system specification (large; section 0.2 has authoritative decisions that override anything else in the doc)

After reading those, you will know:
- What the system is and how it's architected
- What code already exists and is tested
- What still needs to be built (six remaining batches)
- The conventions and style guide to follow
- What's intentionally not in scope for v1

# CURRENT STATE SUMMARY

**Done and tested (133/133 tests passing):**
- `src/lib/crypto.lua` — SHA-256, HMAC-SHA256, AES-128-CBC, password hashing, token generation
- `src/lib/wire.lua` — canonical serialization, message signing, request/response builders, replay protection
- `src/lib/common.lua` — constants, validators, address parsing, atomic persistence, text-mode UI helpers
- `tests/crypto_test.lua`, `tests/wire_test.lua`, `tests/common_test.lua`

**Not yet built (in build order):**
1. `src/nna_reg.lua` — registry server (~700 lines)
2. `src/nmail_srv.lua` + `src/common_srv.lua` — public mail servers (~700 lines combined; should share a `mail_server.lua` core)
3. `src/pr_client.lua` — mail client (~600 lines)
4. `src/domain_srv.lua` + `src/install_disk.lua` — private domain servers and installer (~400 lines)
5. `src/nna_staff.lua` — N.N.A. office staff terminal (~500 lines)
6. Six dedicated installer scripts for pastebin distribution

# YOUR ROLE

You're taking over as the implementation lead. Specifically I'd like you to:

1. **Verify the existing libraries.** Run the three test files. Confirm 133/133 passes. If anything fails, fix it before moving on.
2. **Set up git** if I haven't already, push to GitHub.
3. **Implement the remaining batches** in the order listed in `STATE.md`. After each batch:
   - Write tests where applicable
   - Confirm everything still works
   - Commit with a descriptive message
   - Push to GitHub
   - Update `STATE.md` to reflect progress
4. **Catch design issues during implementation.** If something in `DESIGN.md` doesn't make sense or has an obvious gap, raise it before assuming. Update the doc when we resolve it.
5. **Help me test in CraftOS-PC.** Walk me through what to set up, what commands to run, what to verify.
6. **Build the final installer scripts** once the system works end-to-end.

# WORKING STYLE I PREFER

- **Be careful, not fast.** The previous Claude wrote 1,800+ lines without bugs; that bar is the bar. Tests-first when possible.
- **Don't skip the doc.** When something changes, update `STATE.md` immediately. When a design question comes up, check `DESIGN.md` § 0.2 first (authoritative decisions live there).
- **Match the existing style.** See § 8 of `STATE.md` for the style guide. Plain procedural Lua, `local M = {}` modules, `C.functionName` for the common library, etc. Don't introduce new patterns without flagging them.
- **Push back on bad ideas.** If I ask for something that conflicts with the design or with good engineering, say so. Don't just do it.
- **Keep commits small and meaningful.** One commit per batch is too coarse; one commit per logical step is fine.
- **Ask before deviating.** If you find a reason to change a design decision, raise it first.

# THE PROJECT'S CONTEXT

This is part of a larger Minecraft world that includes a separately-built airport project (the **WBIA** airport, with NIO AirLounge branding). The airport has its own ledger system and uses the same `f` (fluorin) currency. Postroom and the airport are independent projects that will eventually integrate (the airport will register `@wbia` as a private domain), but that integration is not part of v1.

The "in-world" frame matters because some design choices serve roleplay/atmosphere as much as function. The N.N.A. office being staffed by a player, the install-floppy ceremony, the formal tone of system mail — these are deliberate. Don't optimize them away in the name of "simpler UX." If you're tempted to remove ceremony, ask first.

# ENVIRONMENT

- **Lua version:** Lua 5.3 (CC: Tweaked compatible). The libraries also run on standard Lua 5.3 for testing.
- **Testing:** CraftOS-PC for fast iteration, then in-game for final verification.
- **Hosting:** GitHub for the source repo. Six pastebin installers will be the final distribution.
- **HTTP:** enabled in the user's CC config; installers can use `http.get`.

# FIRST THING I'D LIKE YOU TO DO

Read `README.md`, `STATE.md`, and `DESIGN.md` (focus on § 0.2 then § 1–6). Then tell me:

1. Do you understand the system architecture?
2. Do you see any issues in the existing libraries that I should fix before continuing?
3. What do you want me to do first — set up git, run the tests, start batch 2, or something else?

Don't start writing code yet. Confirm context first.
