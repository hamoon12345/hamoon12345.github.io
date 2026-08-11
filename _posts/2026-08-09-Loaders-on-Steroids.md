---
title: "Loader's on Steroids"
date: 2026-08-09 00:00:00 +0000
categories: [Red Team, tools]
tags: [tool, hardening, opsec, tools]
description: ""
toc: true
image:
  path: /assets/loader.png
  alt: shell code loaders
---

# A Technical Breakdown of a Direct-Syscall APC Loader

NOTE: the collection of loaders and tools can be found here: 
https://github.com/hamoon12345/loaders
---

### Anatomy of a Config-Loader Built to Ghost Past EDR

*A technical teardown of a stealth config-loader: steganographic staging inside benign GIFs, double-layer AES with PRNG scrambling, self-built syscall trampolines that skip EDR hooks, and a two-generation execution story — APC-on-self with a thread-injection fallback, upgraded to pure fiber-based (`SwitchToFiber`) execution with zero thread/APC objects — plus the defensive playbook that actually counters it.*

---


# a quick note on : Environment Controls

NOTE : if you change the number to 1 it will be enabled

1. ***LOADER_DEBUG=0*** : Disable verbose logging.
2. ***LOADER_SELFTEST=0***: Skip self‑test and load staged GIF payload.
3. ***LOADER_SLEEPMASK=0***: Disable the 5‑second Ekko‑style sleep mask.
4. ***LOADER_DWELL_MS=3000***: Change masked dwell duration (ms).

## Table of Contents

1. The Short Version
2. Threat Modeling: What This Thing Actually Is
3. The Entire Technique — Explained Before We Touch Code
4. The Code, Function by Function
5. The Build Side: Builder.exe & the GIF Stager
6. The Byte-Level Deep Dives
7. The Evasion Catalog (Technique → MITRE → Detection)
8. Attack Map × Detection Timeline
9. Defenses — What You Can Actually Do
10. Forensic & IR Playbook
11. Detection Engineering (Rule Sketches)
12. Why Bother? (Threat Perspective)

---

## 1. The Short Version

This is a loader. Loaders are the "delivery drivers" of the malware supply chain — their entire job is to take an encrypted payload that lives innocently inside image files, bring it back to life in memory, and hand it off to something else. They are not the payload themselves; they are the thing that makes the payload exist without ever writing it to disk.

What makes this one interesting is how hard it refuses to look like a loader. There is no obvious binary blob. There is no `WriteProcessMemory` into a remote process. No suspicious `VirtualAlloc` with RWX. No `CreateRemoteThread`. Instead, the attack is decomposed into dozens of tiny, individually-boring steps, and the boring is the point. Boring defeats detection. Boring is the strategy.

Every single step — from the GIF in a `node_modules` folder to the `syscall` that executes the shellcode — is one small lie told to a different sensor. No single sensor sees the whole story, because no single step *looks like anything* on its own. This writeup walks the whole thing: the technique first, then the code, function by function, then what a defender can actually do about it.

If you take nothing else away: **this loader is boring-on-purpose.** The defense that beats it is the one that stops looking for a "malware file" and starts watching for *abnormal process behavior at the kernel boundary.*

---

## 1.5 The Technique in a Nutshell

**Main idea:** a payload-encryption + direct-syscall loader that self-injects into its own thread, randomizes timings and signatures every run, and hides the blob in benign GIFs — with two execution generations: APC-on-self (+ `NtCreateThreadEx` fallback) and a fiber-only build that touches no thread, APC, or kernel object at all.

- **Direct syscalls (A1)** — hand-built `NtAllocateVirtualMemory` / `NtProtectVirtualMemory` / `NtCreateThreadEx` trampolines with SSN recovery from memory and disk.
- **Dynamic resolution + SSN recovery (A5/A6)** — exports resolved at runtime; syscall numbers read from memory or the on-disk ntdll PE export table.
- **Custom rolling crypto (B9)** — LCG stream between two AES-128-CBC layers, per-build seeds, decoy fields, junk padding.
- **Never W+X (B10)** — RW alloc → write → sleep-pace → plaintext → flip to `PAGE_EXECUTE_READ` (APC variant); the fiber variant trades this for direct RWX + `FlushInstructionCache`.
- **APC injection (C14 — self-APC)** — `QueueUserAPC(self)` + `SleepEx(0, TRUE)`, so no thread is ever created; executes in the original thread. `NtCreateThreadEx` is only the fallback.
- **Fiber execution (rare, no thread/APC object)** — `ConvertThreadToFiber → CreateFiber(payload) → SwitchToFiber`; a pure user-mode stack switch inside the existing thread, the only path in the fiber-only build.
- **Jump-over-junk polymorphic entry (fiber variant)** — `EB <n>` + 10–30 random bytes prepended to the shellcode so the region's entry-point bytes change every run.
- **Timing/pacing + polymorphism (E25/E28)** — random 2–5 stages × 30–250 ms sleeps + `noise()` decoys + random NOP sleds + per-run RNG.
- **"Looking busy" (E29)** — keep-alive thread sleeping 60 s + noise forever.
- **Fragmented LOTL staging (E30)** — payload hidden in GIF comment blocks across ten `node_modules` folders; no suspicious file ever exists.

---


## 2. Threat Modeling: What This Thing Actually Is

Before the code, a terminology map, because precision matters in a report like this.

| Term | Meaning | Why it matters here |
|---|---|---|
| **Config Loader** | A first-stage component whose output is an encrypted configuration/payload blob | The name says "config" but the mechanics are pure shellcode loading |
| **Shellcode** | Position-independent machine code, run directly from memory | The final product of everything this loader does |
| **Staging** | Hiding payload bytes somewhere innocent | GIF comment blocks inside npm package folders |
| **Direct syscall** | Issuing `syscall` yourself instead of calling the hooked API | Skips the EDR's inline hooks in `ntdll.dll` |
| **SSN** | System Service Number — the integer the kernel uses to dispatch a syscall | The one "secret" a direct-syscall stub needs |
| **Trampoline** | A hand-built function that performs a syscall for you | The loader's replacement for the real API |
| **APC** | Asynchronous Procedure Call — a kernel object that queues a user-mode routine to a thread | The execution vehicle in the APC variant, quieter than thread creation |
| **Alertable wait** | A wait (`SleepEx`, `WaitForSingleObjectEx`) that also delivers queued APCs | The trigger that fires the APC on cue |
| **Fiber** | A user-mode execution context with its own stack, managed by the Fiber API — not a thread, not a kernel object | The fiber variant's execution vehicle; a pure stack switch, even quieter than APC |
| **SwitchToFiber** | The call that hands the CPU from one fiber to another, entirely in user mode | How the fiber variant starts the payload with zero kernel events |
| **Obfuscation vs. Encryption** | Obfuscation defeats signatures; encryption defeats reading | The loader uses both, layered |

### The trust model

A loader like this assumes the following about its target environment:

1. **EDRs hook user-mode APIs** — true for the vast majority of products (CrowdStrike, SentinelOne, Microsoft Defender, Carbon Black, and others all use user-mode/inline instrumentation).
2. **EDRs flag memory that is both writable and executable** — a nearly universal heuristic.
3. **EDRs flag new threads whose start address isn't inside a mapped module** — an extremely common rule.
4. **Sandboxes and AV will see anything written to disk in plaintext** — so nothing sensitive ever *is* on disk in plaintext.
5. **Analysts will triage an alert in seconds** — so the alert must never fire in the first place, or must look mundane when it does.

Every design decision in this loader is downstream of one of those five assumptions. If you understand that, the code writes itself — and so does the defense.

---

## 3. The Entire Technique — Explained Before We Touch Code

Before we look at a single `#include`, you need the mental model. Skip this section and the code will look like random noise. Here is the attack philosophy, from the outside in.

### 3.1 The Delivery Problem

A malicious binary has a problem: any piece of it sitting on disk can be scanned, hashed, signatured, sandboxed, and flagged. So the golden rule of modern loaders is: **lethal artifacts must never exist on disk in a form anyone can recognize.**

This loader achieves that in two ways:

1. The payload is split into pieces and hidden inside **GIF comment blocks** — a legitimate, image-file feature. A GIF is not a payload. Anti-virus scans `node_modules\commander\lib\*.gif`, sees a valid GIF header, and moves on.
2. Even after the pieces are recovered and stitched together, the result is still encrypted. The real payload literally only exists in the correct byte form for the few microseconds between in-memory decryption and execution.

**The principle:** *Never let the truth exist where a sensor is watching.* The truth is permitted to exist — briefly, in memory, under a fake name — only at the exact moment it's needed. Every place the truth would be visible, a decoy is standing in for it.

### 3.2 The Staging Trick: `node_modules` as a Drop Zone

The fragments aren't dropped in one convenient folder. They're scattered across **ten different dependency folders** inside `node_modules`:

```
commander\lib
@types\validator\lib
is-typed-array\test
is-callable\test
define-properties\.github
body-parser\lib\types
acorn-import-attributes\lib
@koromix\koffi-win32-x64\win32_x64
shebang-regex
optionator\lib
```

That folder is a masterclass in camouflage. `node_modules` is a wasteland: thousands of files, no two machines have identical copies, nobody audits it, and every AV has learned to ignore it for performance reasons (scanning 50,000 files on every install would cripple build times). The attacker is betting on **file footprint = attention**. One blob labeled `payload.bin` screams. A handful of GIFs inside `@types\validator\lib`, `is-typed-array\test`, and `body-parser\lib\types` whisper nothing.

Note the deliberate targeting of the paths: they're npm packages that are almost never audited, include icon/inline resources, and live in scoped namespaces (`@types`, `@koromix`) where directory depth throws off simple recursive scans. The `node_modules` tree is used as a **living drop-box**.

### 3.3 Three Layers of Crypto on the Stitched Blob

Once the loader has the concatenated comment data, it runs it through a decryption pipeline that is deliberately not "AES and done":

```
scramble (PRNG seed #7)
   -> AES-128-CBC (key #2)
   -> scramble (PRNG seed #4)
   -> AES-128-CBC (key #1)
   -> scramble (PRNG seed #1)
```

The "scrambles" are a self-made PRNG: a linear congruential generator (`state = state * 1664525 + 1013904223`) whose output is XORed byte-for-byte against the data. It is not real crypto — anyone can invert it — but it doesn't need to be. Its job is **signature obfuscation, not confidentiality**. An analyst hunting for known AES parameters or a specific ciphertext byte pattern has to work through ciphertext that has been pre- and post-XORed with a stateful PRNG. Every layer removes one more "XOR decoration" before the actual AES stage. Defense in depth, where each layer is cheap and the layers multiply the analyst's work.

The keys, IVs, seeds, and original size are all embedded in the blob header. That means the loader is **self-contained**: it needs no network, no C2 call for a key, nothing. It is the key to its own room. Self-sufficiency is itself an evasion and an operational reliability decision: no C2 handshake to fail, no network artifact to catch, no key-exchange to decrypt at rest.

### 3.4 Direct Syscalls: The "Skip the Toll Booth" Trick

This is the centerpiece, so it gets the detail it deserves.

Windows API calls like `NtAllocateVirtualMemory` eventually reach the kernel through the `syscall` instruction in `ntdll.dll`. That function's address is exported and stable, which means an EDR can stand in the path: it overwrites the first few bytes of every `Nt*` function in `ntdll.dll` with a `jmp` into its own monitoring code (this is called **inline hooking**). Every time you call `NtAllocateVirtualMemory`, you — unknowingly — jump into the EDR's inspection code first. That inspection code isn't just logging; it can modify arguments, block the call entirely, or trigger an alert a human analyst sees.

The classic evasion is: **don't call the function at all. Emulate it.** If you know the function's syscall number (SSN), you can build your own little stub that does:

```asm
mov eax, <ssn>      ; load the syscall number
mov r10, rcx        ; the kernel expects the 1st arg in r10, not rcx
syscall             ; straight into the kernel, no hook in the way
ret
```

That's a **direct syscall** — a trampoline that carries you into the kernel while completely bypassing the hooked bytes.

Why `r10`? That's the Windows x64 *kernel ABI*. In the user-mode Win64 calling convention, arguments are passed in `rcx, rdx, r8, r9`. But when the `syscall` instruction executes, the CPU automatically overwrites `rcx` with the return address (Intel semantics) — so the kernel expects the first parameter in `r10`. Every real `ntdll.dll` stub begins with that identical `mov r10, rcx`. This loader faithfully reproduces it. That tiny detail — four bytes, `4c 8b d1` — is the difference between a call that reaches the kernel and one that faults.

But where do you get the SSN? EDRs know you need the SSN, so some of them **patch the SSN-loading instruction inside the hot function** (so reading memory gives you a garbage number). So this loader does SSN recovery in tiers:

1. **Read the in-memory copy**: find the `syscall` instruction (`0f 05`) in the prologue, back up to the nearest `mov eax, imm32` (`b8 ..`), and read the constant. Fast, but readable-your-hooks.
2. **Read from the on-disk PE**: if memory was hooked/patched, pull `ntdll.dll` off the System32 directory from disk (clean copy), parse its PE export table, find the function by name, resolve its RVA to a file offset, locate its `syscall`, and back out the SSN. The on-disk DLL is almost always pristine because most EDRs hook only the mapped, in-memory image.

This is belt-and-suspenders. The loader tries the cheap path first, and *only* if that fails does it do the expensive PE-parsing path. That ordering matters operationally: the disk-mapping path is slower and heavier, so it's reserved for the case where you're already on a heavily-instrumented box.

### 3.5 Signature Randomization on the Trampolines

Here's the problem with direct syscall stubs: the byte pattern `b8 xx xx xx xx 4c 8b d1 0f 05 c3` is **extremely** well known. It's in every YARA rule set under the sun.

The counter: stuff random NOPs in front.

```asm
nop        ; 0..4 of these, chosen randomly per-stub per-run
nop
mov  eax, <ssn>
mov  r10, rcx
syscall
ret
```

Because the NOP count is random (0–4) and chosen per stub per run, the byte offset of the signature shifts every single execution. Signatures that match at a fixed offset break. Because every stub is freshly `VirtualAlloc`'d, even a memory scan that finds one trampoline finds a different-looking one at a different address next time.

It's worth pausing on that, because it's the difference between detection that *almost* works and detection that never fires: **the sample itself is polymorphic at runtime.** And each run of the process re-seeds everything (`time() ^ GetCurrentProcessId()`), so the same *binary* produces a different memory footprint every single execution. Correlation across runs collapses.

### 3.6 Never W and X at the Same Time

Memory that is both writable and executable (`RWX`) is the single loudest memory-protection smell in existence. Almost every EDR/AV heuristic flags it. So this loader plays a careful little dance:

1. Allocate as **RW** (writable, not executable).
2. Write **XOR-encrypted** shellcode into it.
3. Sleep random tens-of-milliseconds blocks with "noise" computation in between (breaking the perfect alloc→write→flip→execute temporal chain that sandboxes look for).
4. Decrypt **in place** to plaintext.
5. Flip the region to **RX** with `NtProtectVirtualMemory` (read + execute, not writable).

At no point is the region both writable AND executable. Even the final content is `PAGE_EXECUTE_READ`, which is exactly what legitimate loaded modules look like. The classic "RWX region containing non-image bytes" telemetry simply never occurs.

### 3.7 Random Pacing & Decoys: Attacking the Timeline

Memory forensics never sees a single "moment." It sees correlations across events: alloc happened, then a write, then a protect, then execution — all in microseconds. That *is* the signal a sandbox correlates on. So this loader inserts **time and noise** into the middle of that chain.

- The number of pacing stages is random: 2–5.
- Each stage sleeps a random 30–250 ms.
- Between sleeps, a `noise()` function churns registers doing meaningless arithmetic — inserting processor-level variation into the timeline.

An analyst correlating "allocation + write + protect + execute within one scheduling quantum" sees a process that allocated memory, slept, did some work, slept again, wrote something, slept again... The *temporal density* of the attack is deliberately destroyed. Because `rand()` is seeded with a time-variant value, the timeline of every run is different — no two runs correlate with each other either.

### 3.8 APC Injection: Run Code Without Creating a Thread

Creating a thread in a fresh executable region — `NtCreateThreadEx(startAddress = freshly-allocated region)` — is a **textbook behavioral alert**. EDRs correlate "new thread" + "start address outside a known module" and raise the flag immediately. That's such a common signal that doing it at all is almost a self-flag.

The quieter path is an **APC** (Asynchronous Procedure Call):

```asm
; apc_stub — 12 bytes of machine code
mov rax, <payload addr>
jmp rax
```

The loader queues that tiny stub as an APC on **its own current thread**, then calls `SleepEx(0, TRUE)` — an alertable wait. When a thread enters an alertable wait, every APC queued against it fires, in order. The APC routine executes its 12 bytes: `mov rax, <addr>; jmp rax`. Control lands inside the shellcode. **No thread is created.** No `CreateRemoteThread`. No `NtCreateThreadEx` event in the trace.

From an event-stream standpoint: a thread slept, and in response, some code ran. Nothing was "created." Any EDR that relies on "new thread object" as its signal completely misses it — which is exactly the design goal. It's a *user-mode* APC (kernel APCs fire in kernel mode; user APCs fire in user mode and require an alertable wait), so the entire payload executes at the original thread's privilege level with the original thread's context intact.

And if APC is somehow blocked (some policy engines disable APC queueing), it degrades gracefully to the direct-syscall `NtCreateThreadEx` fallback — because even the fallback is a trampoline that the EDR can't hook. The fallback is *still* quieter than the normal path most malware uses: it's a direct syscall, unlogged by API hooks.

### 3.9 Fiber-Based Execution: No Thread, No APC — Just a Stack Switch

There is a quieter step *above* APC. Windows has a user-mode scheduling primitive called a **fiber** — a lightweight execution context with its own stack, managed entirely in user space by the Fiber API. A fiber is not a thread, not an APC, not even a kernel object. It is a `CONTEXT`-shaped block of memory the loader can create and switch to with pure user-mode code. No thread is created, no APC is queued, no scheduler involvement is needed — execution is handed over with a single `SwitchToFiber` call that the OS treats as an ordinary function call.

The pattern in the fiber-only loader is three calls and one jump:

```c
LPVOID main_fiber = ConvertThreadToFiber(NULL);            // 1. current thread becomes a fiber
LPVOID payload_fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)remote, NULL); // 2. fiber whose "main" is the payload
SwitchToFiber(payload_fiber);                              // 3. hand the CPU to the payload
```

1. **`ConvertThreadToFiber(NULL)`** — the thread must be a fiber before it can switch. This converts the current (main) thread in place. From the OS's view nothing changed: still one thread, same TID, same process.
2. **`CreateFiber(0, (LPFIBER_START_ROUTINE)remote, NULL)`** — allocates a fiber with its own stack (size 0 = default) whose start routine *is the shellcode address*. The fiber API calls that address exactly like a function, passing `NULL` in the parameter register.
3. **`SwitchToFiber(payload_fiber)`** — saves the current fiber's registers and loads the payload fiber's context, so the CPU begins executing at `remote`. This is a user-mode `jmp` between stacks — no kernel transition, no new thread object, no APC.

Why is this quieter than APC?

- **APC leaves an object.** `QueueUserAPC` creates a kernel APC object attached to a thread; `SleepEx(0, TRUE)` is a detectable call pattern. Fiber switching touches **no kernel object at all**.
- **No alertable wait.** APC requires the thread to enter an alertable state. The fiber path just *switches*.
- **No thread creation.** Neither `NtCreateThreadEx` nor any thread-start event ever fires. A sensor watching for "new thread whose start address is outside a mapped module" sees nothing — the thread that's running is the same one that has been running since the loader started.
- **Low telemetry by rarity.** The Fiber API (`ConvertThreadToFiber`, `CreateFiber`, `SwitchToFiber`) is used by legitimate apps (coroutine libraries, some middleware, game engines), so the API names themselves are far below most EDR alert thresholds.

The one structural cost: **the payload must not assume a thread context.** Fiber stacks are allocated by the fiber API, not by the thread scheduler, so any shellcode that reads `TEB`/`TIB` thread-local data or relies on thread-stack layout quirks may behave differently. For position-independent shellcode that only touches its own stack — which is the normal case for a loader's second stage — this is a non-issue.

In the fiber-only build, this is the *only* execution path: if `ConvertThreadToFiber` or `CreateFiber` fails, the loader frees the region and returns — there is no APC fallback and no thread fallback. That's a deliberate simplification: one quiet primitive, nothing louder in reserve to be caught.

The fiber variant also changes the *staging* shape: it prepends a **jump-over-junk** polymorphic header (`EB <n>` + n random bytes) to the payload before encryption, so the region's entry-point byte layout changes on every run, and it allocates the region as RWX directly rather than walking RW→RX. Both details are documented in §4.7.

### 3.10 Keep-Alive & "Looking Busy"

After delivery, the loader doesn't exit — it runs a keep-alive thread that sleeps 60 seconds and computes `noise()` every tick, forever. The process remains:

- **Alive** (so nothing looks like it "exited after doing something weird").
- **Non-idle-looking** (a process that does periodic work reads as a daemon, not a malware runner).
- **Quiet** (nothing happens on the network, disk, or registry).

The keep-alive loop also provides a natural hook for whatever the payload sets in motion: it can rely on the host process not going away. This is the difference between a "fire-and-forget shellcode runner" and something with operational staying power.

### 3.11 Process Hygiene & Anti-Sandbox Touch

- **RNG seeding with `time() ^ GetCurrentProcessId()`** makes every run behaviorally unique — unique NOP layouts, unique sleeps, unique XOR keys, unique stub addresses.
- **`LOADER_DEBUG` environment toggle** silently disables verbosity in production. Default-off logging is how the sample stays quiet when it shouldn't narrate; the toggle exists only for the operator's lab.
- **Lazy path discovery** (`resolve_project_root`) walks up *from the executable's own directory* looking for the `node_modules` stamp. It's not hardcoded to one absolute path, so the payload tree can live at any depth relative to where the process launched.
- **Deterministic GIF selection** (lexically smallest filename) means the operator and the loader always agree on *which* file is stage N — no ordering ambiguity when the payload is re-staged.

### 3.12 The Overall Chain

The chain below shows the *evolution* of execution methods. The two build variants:

- **APC variant** (original): primary `QueueUserAPC + SleepEx(0, TRUE)`, fallback `NtCreateThreadEx`.
- **Fiber variant** (newest, `config-loader-fiber-only.c`): `SwitchToFiber` **only** — no APC, no thread. It also adds a *jump-over-junk* prepend (see §4.7) and allocates the region as RWX directly rather than RW→RX.

```
 GIFs in node_modules (innocent, on disk)
        │  walk staging paths, read comment blocks (0x21 0xFE)
        ▼
 concatenated blob (obfuscated)
        │  scramble/AES/scramble/AES/scramble
        ▼
 plaintext shellcode (only exists briefly, in memory)
        │  XOR-obfuscate in memory
        ▼
 region ← ciphertext → (paced) → plaintext
        │  RW → RX  (APC variant)   |   RWX direct  (fiber variant)
        │
        ├─ APC variant:  primary APC on self + SleepEx(0, TRUE)
        │                └─ fallback: direct-syscall NtCreateThreadEx
        │
        └─ fiber variant: ConvertThreadToFiber → CreateFiber(payload)
                         → SwitchToFiber   (only path, nothing louder)
        ▼
 payload executes in the same process
        │
        ▼
 keep-alive: Sleep(60s) + noise()  forever
```

**One-line summary of the architecture:** *nothing recognizable ever touches disk; nothing loud ever happens in memory; nothing creates a thread (and in the fiber variant, not even an APC object); and every step happens behind a decoy, a sleep, or a fresh allocation that looks different each run.*

That's the whole play. Now we walk the code.

---

## 4. The Code, Function by Function

### 4.1 Diagnostics: `debug()`, `rand_range()`, `noise()`

```c
static int debug_enabled = -1;
static void debug(const char *fmt, ...) { ... }
```

`debug()` is a timestampped `printf` fronted by an environment-variable toggle. If `LOADER_DEBUG` is set to anything but `"0"`, the loader narrates its own actions to stdout with a `[loader] YYYY-MM-DDTHH:MM:SS ` prefix. The `-1` initial value means "unset", so the check runs once and caches the result — Linux-style lazy init in C. For us, it's the loader's internal breadcrumb trail; for the operator, it's how you watch the whole pipeline live. In a real deployment it's silent by default and writes nothing.

Notice the *format* — ISO-8601 timestamps, a `[loader]` tag, `fflush(stdout)` after every line. This is designed not just to be read by a human but to be grep-able and log-parseable. The operator runs the loader with `LOADER_DEBUG=1` in a lab, watches each stage, and compares stage timing across runs. In production, it's off. That's an anti-forensic choice: the loud code path is toggled by an env var so the shipped sample stays quiet by default.

```c
static int rand_range(int min, int max) { ... }
```

A tiny helper wrapping `rand()` to give an integer in `[min, max]`. It feeds basically every "randomize it" decision in the file: NOP sled lengths, pacing sleeps, XOR key bytes, stage counts. It is *not* cryptographically random — but it doesn't need to be. Its job is behavioral variety, not key strength. Using a weak PRNG is itself a deliberate tradeoff: strong randomness would either add an API dependency (`BCryptGenRandom`, a signal) or create detectable patterns; a seeded LCG produces variety with zero extra dependencies.

```c
static unsigned int noise(void) { ... loop with 0x9e3779b9 ... }
```

`noise()` exists to do arithmetic that is completely meaningless but consumes CPU cycles at irregular points in the execution — pauses to break timing analysis. The constant `0x9e3779b9` is the golden-ratio constant from Knuth's multiplicative hashing; it's there purely to look intentional and churn a register. Because its loop count is fixed (100 iterations), its runtime is roughly consistent on a given machine — which makes the *number* of noise calls per run a mild variance fingerprint: an analyst counting noise invocations per timeline would be confused by the variety.

### 4.2 The Byte Buffer: `ByteBuf`, `bb_init()`, `bb_append()`

```c
typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} ByteBuf;
```

A growable byte buffer — a resizable array with `data`, current `len`, and allocated `cap`. It is the accumulator for the whole staging-and-decryption flow: GIF comments get appended to it, and the resulting blob is what gets decrypted. Structs like this are the *only* data structure the loader uses — no list, no map, no config object. Every extra abstraction is extra surface; the payload tree is linear, and the buffer mirrors that.

```c
static void bb_init(ByteBuf *b) { ... }
static int bb_append(ByteBuf *b, const void *p, size_t n) { ... }
```

`bb_append` grows by doubling (`cap` starts at 4096, doubles until it fits) and `memcpy`s the new bytes in, amortized O(1). Note the failure path returns 0, not `abort` — the loader degrades gracefully if any stage fails, which is deliberate: a *crash* is a signal; a quiet `return 0` is not. There's also a neat anti-overflow property: reads from a GIF are bounds-checked against `len` before appending, so a bogus length byte can't cause an out-of-bounds write.

### 4.3 GIF Extraction: `extract_gif_comments()`

```c
if (data[i] == 0x21 && data[i+1] == 0xfe) {   // 0x21 = extension, 0xFE = comment
```

This is the steganographic extraction core. It walks the raw GIF bytes scanning for the two-byte marker `0x21 0xFE` — in the GIF89a spec, that's "start of a Comment Extension block". For each block it reads sub-block sizes (each payload sub-block is prefixed by a length byte, terminated by a `0x00`), and appends every sub-block's content to the output buffer.

The GIF89a file structure, briefly: `GIF89a` magic + logical screen descriptor + a sequence of blocks. Each block begins with a block-identifier byte:

- `0x21` = Extension introducer
- `0x2C` = Image descriptor
- `0x3B` = Trailer

An extension is `0x21` followed by a *label*; `0xFE` is the Comment label. Comment blocks then contain **sub-blocks**: a length byte, then that many payload bytes, repeated until a zero-length block. This loader simply skims the stream looking for `21 FE` and copying every sub-block payload in sequence.

Because the loader pulls comment content in file order across multiple GIFs, **the payload is literally the concatenation of image captions**. Any image viewer renders these fine. Nothing is damaged; nothing looks anomalous — a GIF's comment field is meant to hold arbitrary text, and the spec permits any byte values. The bits are hidden in plain sight.

### 4.4 Decryption Pipeline

```c
static uint32_t read_u32le(const unsigned char *p) { ... }
```

Unpacks a little-endian 32-bit integer from raw bytes — the loader works with raw packed structures, not `ReadFile` + structs, so all multi-byte values are assembled by hand. Little-endian is the native x64 byte order, but spelling it out explicitly keeps the layout unambiguous.

```c
static void scramble(unsigned char *data, size_t len, uint32_t seed) {
    uint32_t state = seed;
    for (...) {
        state = state * 1664525u + 1013904223u;
        data[i] ^= (unsigned char)(state & 0xff);
    }
}
```

The LCG scrambler. `1664525` and `1013904223` are the textbook ANSI C LCG constants (from the Numerical Recipes / POSIX `rand` lineage). Each byte position advances the PRNG state and XORs one byte of output into the data. It's a stream-cipher-like XOR with a known-generatable keystream — which is exactly why the seeds travel in the header: the loader regenerates the keystream at decrypt time.

This is the "decoy crypto": laypeople call it "AES plus more"; analysts call it "an LCG obfuscation I have to peel off first." Its cryptographic weakness is *intentional*. You are not meant to be unable to decrypt it — you are meant to take noticeably longer to recognize what you're looking at, while the AES beneath it stays obscured by a keystream that changes with every seed. It's friction, applied at scale.

```c
static int aes_cbc_decrypt(const unsigned char key[16], ...)
```

A thin wrapper around the Windows **BCrypt** provider (`BCryptOpenAlgorithmProvider` → `BCryptGenerateSymmetricKey` → `BCryptDecrypt` with `BCRYPT_CHAIN_MODE_CBC`). Note the key is **16 bytes = AES-128**. Two subtle details:

1. **The IV is copied locally per call.** CBC decrypts by chaining blocks, and the BCrypt API updates the IV buffer in place. Reusing a static IV across calls would corrupt the second AES stage's first block. Copying per-call isn't just a bug fix — it means the IV *seen by BCrypt* is never the IV any memory scanner would key on, because it's transient.
2. **The IV and key live in the blob header.** That turns this from "secret-key cryptography" into *self-packaging*: anyone who reverse-engineers the loader can decrypt the payload, but a static scanner can't. The real purpose is work-creation against signature tooling and casual triage, not confidentiality against a determined reverse engineer.

```c
static unsigned char *decrypt_configuration(const unsigned char *blob, size_t len,
                                            size_t *out_len) { ... }
```

The orchestrator. It parses the header (the exact layout the Builder in §5.1 emits):

```
offset 0  : magic           (4 bytes; validated)
offset 4  : original size   (4; clamped to cipher_len later)
offset 8  : cipher length   (4; must be nonzero, multiple of 16)
offset 12 : seed1 .. seed7  (7 × 4 bytes — the real secrets)
offset 40 : key1, iv1, key2, iv2   (4 × 16 bytes, derived from seeds 2/3/5/6)
offset 104: dummy scramble seed    (4 bytes, written 0, ignored)
offset 108: ciphertext (+ optional trailing junk)
```

Then it runs the five-stage inverse pipeline:

```
scramble(seed7) → AES(key2, iv2) → scramble(seed4) → AES(key1, iv1) → scramble(seed1)
```

Buffer hygiene is careful (`free` on every failure path — a leak would accumulate across the keep-alive loop), and `orig_size` is clamped to `cipher_len` so a corrupt header can't cause a length overflow downstream.

Note what is *not* a decoy and what is. In earlier reading of just the loader, seeds `2, 3, 5, 6` looked unused (they're `(void)`-cast in the loader's parser) — but the Builder (see §5.1) reveals they are actually **the key material**: `key1/iv1 ← seed2/seed3`, `key2/iv2 ← seed5/seed6`. The loader doesn't need them because the four key/IV blocks are written into the header directly; it reads those and skips the seeds. So the header carries *redundant* secrets — a classic anti-analysis choice: an analyst reversing only the loader sees seven seeds and must guess which matter; an analyst reversing the full pair sees that the entire cryptographic gate is just `seed1..seed7`. The genuine decoy field is the trailing `dummy scramble seed` (always `0`, skipped by the loader) plus the dead `scramble()` permutation function left in the Builder. That is the entire philosophy of this loader in miniature: **make the analyst's time the scarce resource, not the computation.**

### 4.5 Syscall Trampolines — the heart

```c
static int find_syscall(const unsigned char *prologue, size_t n) {
    for (size_t i = 0; i + 1 < n; i++)
        if (prologue[i] == 0x0f && prologue[i + 1] == 0x05) return (int)i;
    return -1;
}
```

Scans a function's leading bytes for the `syscall` instruction opcode (`0f 05`). On x64 Windows, the `Nt*` functions have a recognizable pattern: `mov r10, rcx; mov eax, <ssn>; syscall; ret`. The loop walks a 64-byte window of the prologue — enough to span any version-to-version variation — and returns the offset of the first `0f 05`.

```c
static int read_syscall_number(...) {
    for (int i = syscall_at - 1; i >= 0; i--)
        if (prologue[i] == 0xb8 && (size_t)i + 4 < n) return read_u32le(prologue + i + 1);
    return -1;
}
```

Walks **backwards** from the `syscall` looking for `0xb8` = `mov eax, imm32`, then reads the 4-byte immediate. That immediate *is* the syscall number. Backwards-walking matters because the `mov r10, rcx` prologue can vary across Windows builds; scanning backwards from the known `syscall` point is version-agnostic — you don't need to know the exact shape of the prologue, only that the constant lands somewhere before the `syscall`.

```c
static int read_ssn_from_disk(const char *func_name) { ... }
```

The fallback SSN source. It maps a **clean copy of ntdll.dll from disk** (`GetSystemDirectoryA` + `CreateFileA` + `CreateFileMappingA` + `MapViewOfFile`), then parses the PE: reads the `MZ` and `PE` signatures, computes the optional-header offset, uses the PE32/PE32+ magic (`0x10b` vs. `0x20b`) to correctly locate the data directory array (offset 96 for PE32, 112 for PE32+), walks the **export table** (`IMAGE_EXPORT_DIRECTORY`: number of names, arrays of functions/names/ordinals as RVAs), resolves each export's RVA to a file offset through the section table, and — when the name matches — runs the same `find_syscall` + `read_syscall_number` dance on the on-disk bytes.

Why does this work when memory is patched? Because **most EDRs patch the mapped copy**, not the file on disk. The disk image is usually pristine, so the SSN recovered from it is correct. The whole exercise is a robust recovery ladder: in-memory copy intact → use it; hooked/patched → reconstruct from the file; *that* fails → give up gracefully and don't crash. Crashing would be a tell.

```c
static void *build_syscall_stub_with_random(const char *func_name) { ... }
```

The assembly step. It resolves the export, extracts the SSN (memory-first, disk-fallback), then hand-builds a stub:

```asm
[0..4 NOPs]      ← random sled, signature breaking
b8 <ssn>         ← mov eax, ssn
4c 8b d1         ← mov r10, rcx  (kernel ABI expects arg in r10)
0f 05            ← syscall
c3               ← ret
```

It's `VirtualAlloc`'d as `PAGE_EXECUTE_READWRITE`, written, then hardened to `PAGE_EXECUTE_READ`. Every stub is therefore a fresh, executable private page containing a hand-crafted syscall. Two consequences:

1. **No static bytes in the binary.** The interesting code is only assembled at runtime — the sample's `.text` section contains zero syscall wrappers to signature.
2. **Call-stack inspection sees an "unknown RX page."** When the EDR unwinds, it sees execution coming *from* a private RX allocation. That's a signal — but an RX-only private page with varying byte layout is a much weaker signal than the classic RWX allocation + fixed-offset syscall pattern. If the EDR's signature requires `b8 4c 8b d1 0f 05` at a fixed offset, the random NOP sled pushes the match off the edge or into a different disassembly shape.

### 4.6 In-Memory Obfuscation: `obfuscate()` / `unapply_obfuscation()`

```c
typedef struct { unsigned char key[4]; int quad; char info[64]; } ObfKey;
```

`ObfKey` records which scheme was used — 4-byte repeating XOR or single-byte XOR — plus the key and a human-readable description (`"xor4 0x2a,0x11,..."` or `"xor1 0x5c"`). The `info` field is operator-facing diagnostic: it's what lets you watch, in the lab, exactly which obfuscation the run selected. It exists so the operator can *verify*, not just trust.

```c
static ObfKey obfuscate(unsigned char *dst, const unsigned char *data, size_t len) { ... }
```

Flips a coin (`rand() & 1`) to pick the XOR scheme, generates a random key, XORs the input into `dst`. Note the chain of randomness: the *scheme itself* is random (1-byte or 4-byte key), and the *key bytes* are random. An analyst trying to statically deobfuscate the shellcode has to first determine which of two schemes was used this run, then brute the key.

The deeper point: this is **not** the decryption crypto. That's the AES+LCG pipeline earlier. This is a separate, in-memory, last-second layer applied just before writing to memory. Its purpose is that the shellcode sitting in the RW buffer is **never in executable plaintext form except in the instant before execution**. A forensic dump taken mid-stage shows only ciphertext.

```c
static void unapply_obfuscation(...) { ... }
```

Exact inverse — strips the in-memory XOR layer when restoring plaintext before the RX flip. The symmetry is what allows "encrypt → stage → decrypt in place" without ever materializing plaintext earlier than needed. The plaintext shellcode exists in that RW buffer for the milliseconds between `memcpy` and the RX flip — and then *it* becomes the payload.

### 4.7 Injection: `execute_shellcode()`

This is the payload-lifecycle manager. Step by step. Two variants exist; the differences are called out where they occur:

- **APC variant** — RW→RX protection flip, APC primary, `NtCreateThreadEx` fallback.
- **Fiber-only variant** (`config-loader-fiber-only.c`) — direct RWX allocation, `SwitchToFiber` as the sole execution path.

**Step 0 — Build the trampolines.**

```c
void *alloc_stub = build_syscall_stub_with_random("NtAllocateVirtualMemory");
void *protect_stub = build_syscall_stub_with_random("NtProtectVirtualMemory");
```

All allocation goes through a direct syscall. The EDR never sees a hooked `NtAllocateVirtualMemory` call; it sees a `syscall`. Function-pointer casts wrap the raw stub addresses into the proper prototypes. Building stubs *first* also means the allocation itself is unhooked — the loader never even touches the real `ntdll.dll` entry point. (The fiber-only build drops the `NtProtectVirtualMemory` stub entirely, since it allocates RWX directly.)

**Step 1 — Prepend a jump over junk (fiber variant).**

```c
int junk_size = rand_range(10, 30);
mutated[0] = 0xEB;            // JMP rel8
mutated[1] = (unsigned char)junk_size;
// junk_size random bytes...
memcpy(mutated + 2 + junk_size, shellcode, len);
```

Before encryption, the payload is prefixed with `EB <n>` — a short jump that skips `n` random junk bytes and lands on the real shellcode. This is polymorphic byte-staging: the *entry-point byte layout* changes every run (10–30 junk bytes), so any signature keyed on the shellcode's leading bytes breaks, and the region starts with harmless-looking garbage rather than a recognizable opcode stream. The jump guarantees execution still lands correctly. The fiber variant then XOR-encrypts the whole mutated buffer (junk + jump + shellcode) before it ever touches the region.

**Step 2 — Encrypt.**

`obfuscate()` makes an XOR'd copy of the shellcode (in the fiber variant, of the *mutated* buffer). Now two buffers exist: the plaintext (about to be discarded) and the ciphertext (about to be written to memory). The plaintext is freed immediately after — the loader's own copy of the truth is as short-lived as the one it will place in memory.

**Step 3 — Allocate, write ciphertext.**

APC variant:

```c
NtAllocateVirtualMemory(process, &remote, 0, &region_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
memcpy(remote, encrypted, len);
```

Region starts as `PAGE_READWRITE` only. No W+X, no flag. The ciphertext is committed. Fiber variant: `PAGE_EXECUTE_READWRITE` directly (RWX) — a trade-off, it skips the protection-flip step but is a noisier allocation flag. Either way, it allocates **in its own process** (`GetCurrentProcess()`) — this is self-injection, not cross-process injection. Cross-process would multiply the suspicious-API surface (OpenProcess, WriteProcessMemory) and add a second process to the trace. Staying in-process keeps the footprint minimal.

**Step 4 — Random pacing + decoys.**

```c
int stages = rand_range(2, 5);
for (...) { Sleep(rand_range(30, 250)); noise(); }
```

2–5 randomized waits of 30–250 ms in between the alloc and the write, with the noise loop chewing cycles. A monitor correlating memory events sees nothing linear: there's no clean "alloc → write → protect → execute" in microsecond succession, and the *number* of intervals is random, so even repeated sampling can't average it out.

**Step 5 — Restore plaintext in place.**

`unapply_obfuscation()` regenerates the plaintext buffer, `memcpy`s it over the ciphertext region. Now memory contains executable-ready shellcode (plus, in the fiber variant, its `EB`-junk header). The fiber variant follows with `FlushInstructionCache()` to guarantee the freshly written bytes are visible to the CPU's instruction fetch before `SwitchToFiber` executes them. The plaintext buffer is freed; the only remaining copy lives in the region destined for execution.

**Step 6 (APC variant) — Flip to RX.**

```c
NtProtectVirtualMemory(process, &protect_base, &protect_size, PAGE_EXECUTE_READ, &old_protect);
```

`PAGE_READWRITE` → `PAGE_EXECUTE_READ`. The final state is RX only — the "proper" look for an executable module. The `old_protect` output argument is also a diagnostic: it proves to the operator's log line what the protection was, which the lab can compare against the timeline. (The fiber variant skips this entirely — it allocated RWX in Step 3.)

**Step 7 — Primary execution: APC on self (APC variant).**

```c
unsigned char apc_stub_bytes[] = { 0x48, 0xB8, ...0xFF, 0xE0 };  // mov rax, imm64; jmp rax
*((void**)(apc_stub_bytes + 2)) = remote;
```

A 12-byte stub: `mov rax, <64-bit shellcode address>; jmp rax`. The immediate is patched with the live address of the payload region, allocated, written, flipped to RX.

```c
QueueUserAPC((PAPCFUNC)apc_stub, GetCurrentThread(), NULL);
SleepEx(0, TRUE);   // alertable wait — fires the APC
```

**No thread is created.** The APC is queued to the current thread; the alertable `SleepEx` causes the kernel to deliver it; the stub jumps into the payload. Every byte of the payload executes **in the original thread** of the loader process. That's the evasion: `NtCreateThreadEx` with a start address inside a data region is an alert an EDR can't miss, but "thread went into alertable sleep, something ran when it woke" is ordinary background noise in every Windows process on earth.

**Step 8 (APC variant) — Fallback: direct-syscall NtCreateThreadEx.**

```c
void *thread_stub = build_syscall_stub_with_random("NtCreateThreadEx");
NtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS, NULL, process, remote, NULL, FALSE, 0,0,0,NULL);
```

If `QueueUserAPC` fails (some hardened configurations block APC queues), it spins up the fallback — still through a raw syscall trampoline, so even the loud path is hook-free. `THREAD_ALL_ACCESS`, `CreateSuspended=FALSE` → the thread starts immediately on the payload region. The handle is closed immediately after creation; the loader doesn't keep a lingering handle to inspect.

**Step 7 (fiber variant) — Execute via `SwitchToFiber`. The only path.**

```c
LPVOID main_fiber   = ConvertThreadToFiber(NULL);
LPVOID payload_fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)remote, NULL);
SwitchToFiber(payload_fiber);
```

`ConvertThreadToFiber(NULL)` turns the current thread into a fiber; `CreateFiber` builds a fiber whose entry point is the payload (with its jump-over-junk header already in place); `SwitchToFiber` hands the CPU to it. No thread object, no APC object, no alertable wait — a pure user-mode stack switch inside the running thread. If either fiber call fails, the loader frees the region and returns `0`; there is deliberately **no fallback** — the fiber is the whole show.

Success returns 1, and the loader proceeds to keep-alive.

### 4.8 Keep-Alive: `keep_alive_proc()`

```c
for (;;) { Sleep(60000); noise(); }
```

A background thread that does nothing but sleep a minute and compute noise — the "I am a boring long-running process" costume. It keeps the process alive and non-idle-looking on a 60-second heartbeat. It serves two masters: the *infection* (the payload process never exits, so anything depending on the host keeps working) and the *cover story* (a process doing periodic busywork reads as a daemon).

### 4.9 Staging & Deployment

`file_exists()` / `dir_exists()` are trivial attribute checks (`GetFileAttributesA`, distinguishing a directory from a file).

`resolve_project_root()` is path discovery with an `LOADER_ROOT` override first, then walks up from the executable's directory (up to depth 12) probing for a directory containing `node_modules\commander\lib` — i.e., it **finds where the GIFs live relative to the running binary**, falling back to the current working directory. The `LOADER_ROOT` override is the operator's lab convenience; the upward-walk is the deployment flexibility.

`first_gif_in()` picks a GIF deterministically: lexically smallest filename in the folder (so the selection is stable across runs and reproducible for the operator). `read_file()` loads it into memory via standard C library calls. `collect_staged_payload()` iterates the ten staging paths, extracts the comments from each GIF in order, concatenating them into the blob — and only counts a stage as "part of the payload" when it produced bytes. If *no* stage produced bytes, it aborts cleanly (returning 0), which the deploy layer handles without crashing.

`deploy()` is the top-level orchestration:

1. Start a keep-alive thread.
2. Collect the staged GIF blob.
3. Decrypt it.
4. Hand it to `execute_shellcode`.
5. Loop sleeping forever (process persists).

`main()` seeds the RNG with `time() ^ GetCurrentProcessId()` — guaranteeing every run gets unique timing, unique NOP sleds, unique XOR keys — then calls `deploy()`. Nothing else. The whole attack is one process with one purpose.

---

## 5. The Build Side: Builder.exe & the GIF Stager

The loader is only half the story. Every stage of the attack needs a *producer* — something that made the encrypted blob, and something that hid it inside the GIFs. Those two tools are the **Builder** (C++) and the **GIF Stager** (Python). They are the encryption side and the staging side of the exact same pipeline the C loader runs in reverse. Read them side by side with §4.4 and §4.3 and you'll see a closed loop: the Builder produces the blob format the loader's `decrypt_configuration()` parses, and the Stager produces exactly the GIF structure the loader's `extract_gif_comments()` walks.

The full build chain is now:

```
shellcode.bin  (raw position-independent payload)
      │  Builder.exe shellcode.bin output.bin [junk_mb]
      ▼
output.bin  (blob: header + 3×xor + 2×AES-128-CBC ciphertext [+ junk])
      │  embed_gif_visible.py output.bin 10
      ▼
10 GIFs across node_modules\<10 folders>  (comment blocks carry blob chunks)
      │  config-loader (deploy → collect → decrypt → execute)
      ▼
payload runs in the loader's own process
```

### 5.1 Builder.exe — the encryption side

**Purpose:** convert raw shellcode into the exact encrypted container the C loader can decrypt. Every crypto decision on this side has to match the loader's decryption step-for-step — same LCG constants, same AES-128-CBC, same header layout, same byte order. That coupling is the whole point: it's a matched pair.

**Hand-rolled AES-128 (encryption only).** The Builder *does not* use the Windows `BCrypt` provider or OpenSSL. It ships a complete, self-contained AES-128 implementation — S-box, `Rcon` round constants, `KeyExpansion`, `SubBytes`, `ShiftRows`, `MixColumns`, and the 10-round `Cipher` — then wraps it in `AES128_CBC_encrypt` with PKCS-style zero padding (blocks padded with `0x00`). Why roll your own? Because the loader uses `BCryptDecrypt` on the Windows side, and this C++ tool is meant to run anywhere (cross-platform build machine, CI, or a disposable VM). More subtly: a standalone AES gives the operator a *single, self-contained* build that doesn't leak `bcrypt.lib` or OpenSSL import hints into the build environment — and it keeps the crypto byte-for-byte reproducible so the loader's decrypt and this encrypt are guaranteed compatible.

**`xor_with_prng()`** — the LCG scramble layer, identical to the loader's `scramble()`. Same constants `1664525U` and `1013904223U`, same per-byte `state * c + a` XOR. This is the "decoy crypto" — it's not confidentiality, it's signature-friction between AES layers.

**`scramble()` (defined but never called).** A *permutation-based* shuffle using `std::mt19937` + `std::shuffle`. It's dead code — explicitly left in, explicitly unused, and explicitly commented out in `main`. That's deliberate: an analyst reversing the Builder sees a second obfuscation layer and burns time testing whether the blob went through it. It's the same "multiplication of effort" trick as the decoy seeds in the loader's header. In this writeup, the actual pipeline is: `xor(seed1) → AES(key1,iv1) → xor(seed4) → AES(key2,iv2) → xor(seed7)` — *no* permutation scramble.

**Key/IV derivation.** The Builder derives AES keys and IVs *from the seeds* rather than generating them independently:

```cpp
key1[i] = (seed2 >> (i*2)) & 0xFF;   // key1 from seed2, iv1 from seed3
iv1[i]  = (seed3 >> (i*2)) & 0xFF;
key2[i] = (seed5 >> (i*2)) & 0xFF;   // key2 from seed5, iv2 from seed6
iv2[i]  = (seed6 >> (i*2)) & 0xFF;
```

So the actual secrets of the blob are `seed1..seed7` — everything else (key1/iv1/key2/iv2, the sizes, even the "scramble seed") is *derived or decoy*. This is a meaningful simplification for the attacker: seven 32-bit seeds, all written in plaintext to the header, are the entire cryptographic gate. It also means the "128-bit AES keys" are effectively derived from a 32-bit seed each — a *deliberate* reduction in strength in exchange for operational simplicity. Nothing here protects against a determined reverser; it only slows signature-first tooling.

**Junk padding.** `generate_junk()` and the optional `[junk_mb]` CLI argument append random bytes *after* the ciphertext. Two effects: (1) the on-disk blob's real payload is diluted, and (2) `cipher_len` in the header records the length *without* junk, so the loader knows exactly how many bytes to decrypt and silently ignores the rest. That's a cheap way to make the shipping artifact look bigger and messier than it is.

**Header emission.** The Builder writes, in this exact order:

```
magic(4) | orig_size(4) | cipher_len(4) | seed1..seed7(28) |
key1(16) | iv1(16) | key2(16) | iv2(16) | dummy_scramble(4) |
ciphertext(+junk)
```

This is a byte-for-byte match to what the loader's header parser expects (see §4.4). Note `dummy_scramble` is written as `0` and *ignored* by the loader — one more decoy field in the header.

**Anti-analysis touches.** `std::random_device` seeds `mt19937`, so the blob is fresh on every build — different keys, different IVs, different LCG seed choices each time. No two blobs from the same shellcode are identical, which defeats hashing and deduplication at the file level.

### 5.2 embed_gif_visible.py — the staging side

**Purpose:** take the blob produced by Builder.exe and hide it inside *visible, renderable GIF files* that live in the ten target `node_modules` folders. The loader's `extract_gif_comments()` will later walk these exact files.

**`create_visible_gif_bytes()`** — builds a real 200×200 blue GIF with the text `lib` drawn on it, using PIL. This is the crucial refinement: the carrier isn't a broken/blank GIF, it's a *legitimate, viewable image*. It renders in any image viewer, passes format validation, and looks like an innocuous icon asset. If the operator wants, the visible content can be swapped for anything — a logo, a chart, a screenshot — because the payload lives in comment metadata, not in the image data.

**`inject_comment_blocks()`** — the steganographic writer, and the exact inverse of the loader's `extract_gif_comments()`:

```
for each chunk:
    0x21 (extension introducer) + 0xFE (comment label)
    for each 255-byte piece:  <len> <piece bytes>
    0x00 (sub-block terminator)
```

It locates the GIF trailer (`0x3B`), inserts all comment blocks immediately before it, and splices. This is spec-legal GIF89a. The loader's extractor finds these blocks, concatenates the sub-block payloads in order, and rebuilds the blob — a perfectly symmetric pair.

**Chunking.** The blob is split into **255-byte chunks** — the maximum GIF sub-block size — and distributed round-robin across the target folders (`chunks_per_file = ceil(total / num_files)`). The `@types\validator\lib`, `body-parser\lib\types`, etc. paths in `TARGET_FOLDERS` are exactly the loader's `STAGING_PATHS` (forward slashes in Python vs. backslashes in C — same folders).

**`clear_existing_gifs()`** — deletes any `.gif` already in each target folder before writing the new `asset_N.gif`. This is build hygiene: it guarantees the folder contains exactly the current stage's GIFs, so the loader's "first `.gif` in folder" selection picks up the fresh payload and not a stale one. It also gives the loader a deterministic, known set to walk.

**Determinism.** The GIFs are named `asset_1.gif` … `asset_N.gif` and each folder holds exactly one — matching the loader's `first_gif_in()` which takes the lexically smallest `.gif` (see §4.9). The builder, stager, and loader all agree on *which file holds which chunk*, with zero coordination at runtime.

### 5.3 The matched-pair contract

| Builder emits | Loader consumes | Match |
|---|---|---|
| `xor(seed1) → AES1 → xor(seed4) → AES2 → xor(seed7)` | `scramble(seed7) → AES2⁻¹ → scramble(seed4) → AES1⁻¹ → scramble(seed1)` | LCG constants identical (1664525 / 1013904223) |
| `key1/iv1 ← seed2/seed3`, `key2/iv2 ← seed5/seed6` | keys/IVs read directly from header | Same 16-byte values |
| header: magic, orig, cipher_len, 7 seeds, 4×16 key/IV, dummy(4) | parses identical layout, skips dummy | Byte-for-byte |
| 255-byte sub-blocks in GIF comment extensions | `extract_gif_comments` reassembles in order | Spec-legal GIF89a |
| `asset_N.gif` one-per-folder | `first_gif_in` picks it deterministically | No runtime coordination needed |

If you see one of these tools in the wild, you now know exactly what the other side looks like — and the loader's own header hands you the decryption key, so the *entire* build chain can be unwound from a single blob.

---

## 6. The Byte-Level Deep Dives

### 6.1 The GIF89a Comment Extension, byte by byte

A GIF file is a stream of blocks. The relevant grammar:

```
Extension introducer:  0x21
Label:                 0xFE   (Comment)
Sub-block:             <len> <that-many-bytes>
Sub-block terminator:  0x00
```

So the fragment carrier inside the file looks like:

```
21 FE 18 41 53 31 2b 2b 61 6c 70 3d 2b 30 2b 2b 78 66 32 1a 6c 77 0e 11 0f 00
     \___________/
       24 bytes of payload fragment (0x18 = 24)
```

This is why the extraction loop structure is: `0x21 → expect 0xFE → read len → copy len bytes → repeat until len==0`. It is *exactly* the GIF spec. Nothing a well-written GIF decoder would choke on, and any hex editor will show a legitimate Comment Extension with plausible content.

**Detection angle:** comment text that is uniformly high-entropy (incompressible, flat histogram) across many bytes is abnormal for captions. A 3–4 KB comment block that compresses to nothing is nearly proof of staging — but you have to actually count entropy across comment blocks, which almost no product does deeply.

### 6.2 The ntdll.dll syscall prologue

A standard x64 `Nt*` stub in `ntdll.dll`:

```asm
; Windows 10/11 x64, e.g. NtAllocateVirtualMemory
4c 8b d1          mov     r10, rcx
b8 xx xx xx xx    mov     eax, <SSN>
0f 05             syscall
c3                ret
```

The ABI rule: the syscall number rides in `eax`; the first user argument must be in `r10` (because `rcx` is clobbered by `syscall` on Intel as the return address). The loader's trampoline reproduces this exactly. Every modern EDR and malware toolkit fights over *this specific 14-byte window*.

**Detection angle:** execution returning from `syscall` into a *private, non-image* RX page is the definitive direct-syscall signal. No legitimate library does that.

### 6.3 The PE export-table parse (`read_ssn_from_disk`)

Recovery from disk requires walking:

- `IMAGE_DOS_HEADER` → `e_lfanew` (offset `0x3c`) → `PE` signature.
- `IMAGE_FILE_HEADER.NumberOfSections` (offset `+6`), `SizeOfOptionalHeader` (`+20`).
- Optional-header magic: `0x10b` = PE32 (data directory at `+96`), `0x20b` = PE32+ (at `+112`).
- `IMAGE_EXPORT_DIRECTORY`: `AddressOfFunctions` (`+28`), `AddressOfNames` (`+32`), `AddressOfNameOrdinals` (`+36`), `NumberOfNames` (`+24`).
- For name `i`: name RVA → file offset → `strcmp` → ordinal `i` → function RVA → file offset → scan 64 bytes → `syscall` → `mov eax` → SSN.

The loader reimplements PE loader math by hand — not because it can't use `GetModuleHandle` (it can), but because it must resolve **file offsets**, not virtual addresses. RVA→file-offset conversion uses the section table: for each section, `VirtualAddress ≤ rva < VirtualAddress + SizeOfRawData` → `rva - VirtualAddress + PointerToRawData`. The code reads *on-disk* bytes, where section alignment differs — hence `SizeOfRawData`, not `VirtualSize`.

**Detection angle:** reading `C:\Windows\System32\ntdll.dll` directly by path is a mild anomaly in benign code — and a fantastic forensic hook, because the on-disk bytes can be stashed/hashed for comparison.

---

## 7. The Evasion Catalog (Technique → MITRE → Detection)

| # | Evasion technique | Where | MITRE ATT&CK (approx.) | What it dodges | What beats it |
|---|---|---|---|---|---|
| 1 | Payload staged in GIF Comment Extensions | `extract_gif_comments` | T1027.002 / T1036.005 | Static AV scanning, file-carving | Entropy scan on comment blocks; npm integrity hashing |
| 2 | Fragments scattered across npm folders | `STAGING_PATHS` / `collect_staged_payload` | T1074 / T1027.002 | Recursive-folder AV, baselining | Package-lock + artifact verification |
| 3 | LCG scrambling between AES layers | `scramble` | T1027.001 | Signature matching on ciphertext | Statistical analysis; in-lab decrypt chain inversion |
| 4 | Double AES-128-CBC | `aes_cbc_decrypt` | T1027.013 / T1140 | Static identification of payload | Memory dump at final decrypt; header key extraction |
| 5 | Redundant secrets in header (seeds carry the keys) | `decrypt_configuration` | T1027.007 | Static analysis effort | Reverse the Builder; seed2/3 → key1/iv1, seed5/6 → key2/iv2 |
| 6 | Self-contained keys (no C2) | header keys + IVs | (no C2 traffic) | Network IOCs | Runtime memory/ETW key extraction |
| 7 | Direct syscall trampolines | `build_syscall_stub_with_random` | T1106 / T1129 | API inline hooks | Kernel callbacks, ETW SysCall / Threat-Intel, CET |
| 8 | SSN recovery from memory *and* disk | `read_ssn_from_disk` | (reflection-ish) | SSN-patching EDRs | Detection of mapping ntdll from disk |
| 9 | Random NOP sled on trampolines | `build_...` | T1027 (mutation) | Fixed-offset YARA, RWX heuristics | Behavioral "syscall from private RX" rule |
| 10 | Allocate RW → flip to RX (APC variant) / direct RWX (fiber variant) | Steps 2–5 | T1055 / T1106 | RWX heuristics | Protection-transition telemetry; kernel PTE audit; RWX alloc-call anomaly |
| 11 | In-memory XOR before staging | `obfuscate` / `unapply` | T1140 / T1027 | Memory scanning mid-stage | Dump at the right moment |
| 12 | Random pacing + noise decoys | Steps 3 / keep-alive | T1497.001/.003 | Time/behavior sandboxing | Longer-run monitoring; statistical profiling |
| 13 | APC + alertable-wait self-injection (APC variant) | Step 7 | T1055.004 / T1134-ish | Thread-creation alerts | "APC target executes private RX code" rule |
| 14 | Fallback thread through raw syscall (APC variant) | Step 8 | T1055.001 / T1106 | Hooked-API telemetry | Kernel thread-start events (Threat-Intel ETW) |
| 15 | Fiber execution via `SwitchToFiber` (fiber variant) | Step 7 (fiber) | T1055-ish / custom | Thread-creation **and** APC alerts; stack traces | Fiber-switch ETW (rarely instrumented); kernel-mode CSP callback on the region |
| 16 | Jump-over-junk polymorphic entry prepend (fiber variant) | Step 1 (fiber) | T1027 / T1497 | Signatures on shellcode leading bytes | Multi-sample clustering on the `EB` prefix |
| 17 | Keep-alive + noise forever | `keep_alive_proc` | (process persistence) | Idle-process identification | Baseline your own daemons |
| 18 | Per-run RNG seeding | `main` | T1027 / T1497 | Sample correlation, sandbox averages | Threat-intel across runs (they still differ) |
| 19 | Debug via env toggle (silent default) | `debug` | (anti-forensics) | Log noise, analyst triage time | Run with `LOADER_DEBUG`; env-hound telemetry |
| 20 | Fresh blob per build (random seeds/keys) | Builder `main` | T1027 / T1497 | File hashing, AV dedup | Rebuild-too-many; seed-space analysis |
| 21 | Visible, renderable carrier GIFs (not broken files) | Stager `create_visible_gif_bytes` | T1036.005 / T1027.002 | Format validation, human review | Uniform 200×200 blue + `asset_N.gif` naming across 10 folders |
| 22 | Dead decoy code left in the Builder (`scramble`) | Builder | T1027.007 | Static analysis effort | Note & discard; the real chain is xor/AES/xor/AES/xor |

*(MITRE IDs are approximate mappings — this is a composite loader, not a single ATT&CK technique.)*

---

## 8. Attack Map × Detection Timeline

```
┌──────────────────────────────────────────────────────────────────────────┐
│                 ATTACK MAP — the full build-to-execution chain           │
└──────────────────────────────────────────────────────────────────────────┘

 0. BUILD (Off-host — production side, never on the victim)
    shellcode.bin ─▶ Builder.exe shellcode.bin output.bin [junk_mb]
        (xor seed1 → AES1 → xor seed4 → AES2 → xor seed7, header + junk)
              │
              ▼  embed_gif_visible.py output.bin 10
    (blob split into 255-byte chunks, injected into GIF comment blocks)

 1. PERSIST / STAGE (On Disk — Everything Looks Legit)
    ┌───────────────────────────────────────────────┐
    │ node_modules\<10 folders>\   (commander\lib,   │
    │ @types\validator\lib, is-typed-array\test,    │
    │ body-parser\lib\types, ...)                   │
    │     └─ asset_N.gif  (valid, visible 200×200   │
    │         GIF; comment blocks 0x21 0xFE carry   │
    │         the encrypted blob chunks)            │
    └───────────────────────────────────────────────┘
                        │
                        ▼
 2. EXTRACT & STITCH (In Memory)
    walk paths → first_gif_in → extract_gif_comments → concatenate → blob
                        │
                        ▼
 3. DECRYPT PIPELINE (In Memory — layered)
    scramble(seed7) ─▶ AES-128-CBC(k2,iv2) ─▶ scramble(seed4)
        ─▶ AES-128-CBC(k1,iv1) ─▶ scramble(seed1)   ─▶ plaintext shellcode
                        │
                        ▼
 4. MEMORY STAGING
    build NtAllocateVirtualMemory trampoline  (direct syscall, random NOPs)
    APC variant:  NtAllocateVirtualMemory(RW) ─▶ write XOR-ciphertext
                  ─▶ sleep(30–250ms)×(2–5) + noise() decoys
                  ─▶ restore plaintext in place ─▶ NtProtectVirtualMemory(RX)
    fiber variant: NtAllocateVirtualMemory(RWX, direct) ─▶ write XOR-ciphertext
                  ─▶ sleep(30–250ms)×(2–5) + noise() decoys
                  ─▶ restore plaintext + jump-over-junk prepend + FlushInstructionCache
                        │
                        ▼
 5. EXECUTION (No New Thread, No APC — switch stacks)
    APC variant:
        ┌─ PRIMARY:  QueueUserAPC(stub: mov rax,payload; jmp rax, self)
        │            SleepEx(0, TRUE)  ─▶ APC fires ─▶ payload runs in-thread
        └─ FALLBACK: if APC fails ─▶ NtCreateThreadEx via direct syscall trampoline
    fiber variant (only path):
        ConvertThreadToFiber(NULL) ─▶ CreateFiber(payload) ─▶ SwitchToFiber(payload)
                        │
                        ▼
 6. PERSIST (Process stays alive, looking boring)
    keep-alive thread: Sleep(60s) + noise()   forever
```

**Detection timeline — what a sensor actually sees at each stage:**

| Stage | Indicator observed | Which control it dodges | What it looks like to telemetry |
|---|---|---|---|
| 1. GIF in `node_modules` | Valid image file, no PE bytes | Static analysis / signature | A `.gif` among hundreds of `.gif`s |
| 2. Comment extraction | Generic file read + byte scan | Content inspection | An "image loaded"; nothing system-level |
| 3. Decryption pipeline | `BCryptDecrypt` call | Config/file carving | `bcrypt.dll` in module list (nearly universal) |
| 4. Trampoline build | New RX/RWX heap + `syscall` from heap | API hooking, RWX heuristics | RX private allocation (module-like); RWX only in fiber variant |
| 5. Protect flip / prepend | `NtProtectVirtualMemory` direct (APC var.) | RWX heuristics | One RX region that could pass as a module |
| 6. Execution | APC var.: `SleepEx(0, TRUE)`; fiber var.: pure `SwitchToFiber` — zero kernel events | Thread-creation **and** APC alerts | Background noise (APC) or *nothing at all* (fiber) |
| 7. Thread fallback (APC var. only) | Direct syscall `NtCreateThreadEx` | Hooked API telemetry | Kernel thread start w/ private start addr (the one real tell) |
| 8. Keep-alive | Periodic noise, 60s sleep | Idle-process identification | A daemon doing "work" every minute |

The most defensive-relevant insight from this table: **exactly one event is a solid tell** — the thread-start (APC-variant fallback path) or a syscall returning into a private RX/RWX page. The fiber variant is engineered so that even the *APC object* never exists, leaving almost nothing for user-mode telemetry to latch onto. Everything else is designed to look indistinguishable from noise.

---

## 9. Defenses — What You Can Actually Do

The threat is real but not unstoppable. Countering it means attacking the *assumptions* the loader relies on, not chasing its signatures.

### 9.1 Static & Staging Defenses (the supply-chain corner)

- **Software inventory + hashing of `node_modules`.** Take hashes of the `*.gif` files at build/deploy time, store them out-of-band, and alert on any that changed. A GIF payload fragment *must* differ in bytes from the benign baseline — that's the entire trick. This loader's deterministic first-GIF choice makes the hashed path list computable: hash the 10 staging folders, alert on any deviation.
- **Dependency-lockfile integrity.** Pin and verify `node_modules` against a `package-lock.json`; any GIF inside an installed package that differs from the registry artifact is instantly anomalous. Pro tip: GIFs in npm packages are rare and small — a whitelist is cheap and has near-zero false-positive rate.
- **Scan GIF comment extensions for entropy.** A single robust SIG: flag *any* image whose comment extension contains ≥ ~64 bytes of high-entropy (incompressible) data, or any `.gif` that is > ~50% comments. Normal captions compress and are short; encrypted payload fragments are random-looking. **This one rule alone would have buried this campaign.**

  Pseudocode for the SIG:
  ```
  foreach *.gif:
      blocks = parse_comment_blocks(file)
      for b in blocks:
          if len(b.bytes) >= 64 and shannon_entropy(b.bytes) >= 7.5:
              ALERT "suspicious high-entropy GIF comment"
  ```
- **Watch for the `asset_N.gif` cluster.** This exact stager names its carriers `asset_1.gif`…`asset_N.gif`, all 200×200 blue, one per folder, across exactly these ten paths. Flag a fleet-wide pattern of "an `asset_N.gif` appearing in a set of npm folders at the same time" — it's the build-tool footprint leaking onto disk.
- **Limit process launch from `node_modules`.** The loader runs from wherever the GIFs live. Allowlist/restrict which parent directories may spawn processes; executing from a `node_modules` tree is almost always wrong for a server process.
- **Watch for the `C:\Windows\System32\ntdll.dll` read.** `read_ssn_from_disk` maps ntdll by path. Benign code almost never calls `CreateFileA("\System32\ntdll.dll")`. That's a clean, cheap API-level detection.

### 9.2 Runtime & Memory Defenses (the behavioral corner)

- **Enable and enforce CET (Control-flow Enforcement Technology) + EAF.** Trampolines that live on heap-executable pages and are targets of `jmp rax` are *exactly* what shadow-stack + indirect-branch-tracking exists for. On CET-capable CPUs, returning through an unknown indirect target breaks outright. Enable it on all supported endpoints.
- **Monitor memory-protection transitions.** Telemetry on `VirtualProtect`/`NtProtectVirtualMemory` for RW→RX flips on *fresh private allocations* (especially those followed by execution) is a top-tier alert. Legit modules are memory-mapped, not RW-allocated-then-RX-flipped.
- **Instrument the kernel boundary, not the API.** This loader (like all direct-syscall threats) secretly wins against user-mode hooks but *loses* against **kernel callbacks, ETW kernel events, and Sysmon-level telemetry**, which fire *after* the syscall regardless of who issued the instruction. The ETW `Microsoft-Windows-Threat-Intelligence` provider emits `KERNEL_THREATINT_SYS_CALL_*` events natively.
- **Flag "syscall returning into a private RX page."** This is the decisive, near-zero-false-positive signal. No legitimate driver/library returns from a syscall into an anonymous executable heap region.

### 9.3 Behavioral / Process Defenses (the shooter's corner)

- **Thread-creation telemetry at kernel level.** The fallback `NtCreateThreadEx` fires a kernel thread-start event with a start address *outside* any module. That's the single most reliable alert in the whole chain. Wire `KERNEL_THREATINT_THREAD_START` into a high-signal rule.
- **QueueUserAPC / APC abuse policy.** Where platform policy allows, restrict arbitrary APC queueing to critical processes; at minimum, correlate "APC queued on thread" with "thread subsequently executed non-image code."
- **Process Mitigation Policy:** apply `DisableDynamicCode` (Arsenal Image + EMET-style), `BlockNonMicrosoftBinaries` / `MicrosoftSignedOnly`, and CET enforcement — all policies that make an RX-private-allocation + indirect-branch execution materially harder.
- **Baseline your own daemons.** A "keep alive + noise every 60s" process is only invisible if you don't know your own fleet's heartbeat patterns. Normalize and alert on process lifecycles that outlive their expected runtime.

### 9.4 The "kill the cheap math" corner

- **CRC/authenticate your own binaries.** `LOADER_DEBUG` and embedded keys mean the loader can't resist a determined reverse — and the fact that all secrets ship in the header means deterrence is the only real crypto. Your force-multiplier is scale: hash, sign, attest, and make your baseline so thoroughly-known that *any* deviation (a GIF that grew, a timestamp that's off, a 60-second noise thread that exists) flags.

### 9.5 The blunt instrument that still works

- **Modern sandboxes, AMSI, SmartScreen, ML reputation, and signed-publisher policy** still stop a *large fraction* of these when the payload itself (the thing the loader eventually runs) is known. The loader being clean doesn't help the attacker if the *thing it loads* is already flagged. Defense in depth: make the loader very hard to ship, *and* make the payload impossible to hide.

**One line:** *stop watching the API layer, start watching the kernel syscall boundary and memory-protection evolution, and pin your software supply chain so that "a GIF that changed" is itself an alert.*

---

## 10. Forensic & IR Playbook

If you suspect a machine ran something like this, here's the order of operations that maximizes what you recover.

### 10.1 Preserve before you poke

1. **Pull a full memory image first.** The payload's plaintext shellcode exists in memory for milliseconds, but the *evidence of the technique* (trampoline pages, RX regions, the decoder) persists in the process's address space. `DumpIt` / `WinPmem` / a managed host tool — before touching anything else.
2. **Snapshot the `node_modules` tree** (or the staging root) including file hashes, timestamps, and sizes — before any AV "cleans" the GIFs. The GIF fragments are your strongest static evidence: they're the payload *in its hiding place*.
3. **Collect ETW / Sysmon logs** for `ProcessCreate`, `ProcessAccess`, `FileCreate`, `ThreadCreate`, `VirtualProtect` events on the host — the timeline around the launch is the forensic spine.

### 10.2 Memory forensics checklist (Volatility-ish)

- `pslist` / `psscan` → find the loader process and anything whose `start address` is a private allocation rather than a module base. **That is the fallback thread.**
- `malfind` → scan for RX regions whose content isn't a mapped image. The stub pages and the RX-warmed payload region light up.
- `handles` for `\Device\NamedPipe` or suspicious objects owned by the loader process.
- `envars` on the process → check for `LOADER_DEBUG` (forensic breadcrumb: if it's set, the sample was running verbose).
- Correlate `VirtualProtect` transitions in the ETW `Microsoft-Windows-Kernel-Memory` channel — RW→RX flips on a PID are the memory-level replay of the technique.

### 10.3 Static reboot of the GIF stream

1. Pull the 10 staged GIFs.
2. `extract_gif_comments` them (or `hexdump` and grep for `21 fe`).
3. Concatenate sub-block payloads in order.
4. Reconstruct the header: magic + size + cipher_len + 7 seeds + 4×16 key/IV + scramble seed.
5. Run the inverse pipeline: scramble(seed7) → AES(k2,iv2) → scramble(seed4) → AES(k1,iv1) → scramble(seed1).
6. You now have the plaintext payload. That's the whole ceremony — the loader gives you every secret in its own header. The only work is assembling it.

**Shortcut:** if you recover the *Builder* rather than the loader, unwinding is even faster — the keys are derived from the seeds (`key1/iv1 ← seed2/seed3`, `key2/iv2 ← seed5/seed6`), so a single header read gives you every AES key and every LCG seed. And because the Builder derives "128-bit" keys from 32-bit seeds, the effective key space per key is at most 32 bits — brute-force feasible if the seed derivation is confirmed.

### 10.4 What to write into the incident report

- The staging paths (10 folders) and file hashes of the GIFs.
- Blob header fields (seeds, keys, IVs) as artifacts.
- Whether the GIFs match the stager fingerprint (`asset_N.gif`, 200×200, one per folder) — ties the sample to the *specific* build tooling.
- The loader's module list & the trampoline pages observed.
- Which execution path fired (APC vs. thread fallback) — inferable from thread-start events.
- Any payload behaviors observed after delivery (keep-alive threads, network, persistence).

---

## 11. Detection Engineering (Rule Sketches)

### 11.1 File-level (near-zero FP)

**Rule 1 — High-entropy GIF comment:**
```
file.extension != gif  -> ignore
comments = gif_comment_blocks(file)
any block with (len >= 64 AND shannon_entropy >= 7.5)  -> ALERT
```

**Rule 2 — GIF unusually comment-heavy:**
```
if sum(comment_len) / file_size > 0.50 -> ALERT
```

**Rule 3 — Known staging path drift:**
```
for path in [commander/lib, @types/validator/lib, ...]:
    hashset.now  vs  hashset.baseline  -> any diff = ALERT
```

**Rule 3b — Stager artifact cluster:**
```
cluster = all .gif named asset_*.gif in node_modules trees
if any cluster has >= 3 members across the 10 staging paths
   AND each is ~same pixel dims (e.g. 200x200)
   AND comment blocks are high-entropy   -> ALERT "GIF stager footprint"
```

**Rule 4 — `ntdll.dll` read by path from a non-trusted process:**
```
process.image NOT IN (whitelist) AND
target.file == "\Windows\System32\ntdll.dll" -> ALERT
```

### 11.2 Runtime / behavioral

**Rule 5 — Syscall returning into private RX:**
```
kerneltrace has syscall return address in a private-memory RX range
-> ALERT (direct syscall)
```

**Rule 6 — RW→RX flips on fresh private allocations:**
```
event = VirtualProtect(old=READWRITE, new=EXECUTE_READ)
region.start_age < 5 minutes
-> ALERT
```

**Rule 7 — Thread start into unbacked region (fallback path):**
```
thread_create.start_address NOT IN any mapped image range
-> ALERT
```

**Rule 8 — Alertable-wait followed by non-image execution:**
```
SleepEx(..., Alertable=TRUE) observed, then
execution resumes in private allocation
-> ALERT (APC execution)
```

**Rule 9 — Fiber API used with a payload-like start address (fiber variant):**
```
CreateFiber / ConvertThreadToFiber / SwitchToFiber observed in a process
NOT in the fiber-using allowlist (no JS runtime, no coroutine lib)
AND the fiber start routine is NOT inside a mapped image range
AND the region was recently allocated as private memory
-> ALERT (fiber-based execution)
```
*This is the one user-mode hook a fiber-only loader leaves, but it requires both Fiber-API telemetry *and* start-address resolution — most EDRs instrument neither, which is exactly why the technique is quiet. The switch itself emits no kernel event, so the rule keys on the API names themselves; without the allowlist the FP rate is too high, and without start-address resolution (kernel CSP callback or post-switch stack-walk) it can't confirm the kill.*

### 11.3 Operationally

- Baseline your own `node_modules` trees in CI and on fleets; any drift is an incident candidate.
- Run the SIG on every `.gif` ingested into your repositories (you may be shipping the drop for someone else).
- Keep CET/EMET hardening on everywhere it's supported; it deprioritizes a whole class of these.

---

## 12. Why Bother? (Threat Perspective)

If you read this and wonder "why would someone hand-build LCG scramblers and NOP-sledged trampolines instead of just downloading an obfuscator": because **loaders are the most-scanned, most-triaged link of the chain**. The payload your sensor flags becomes a YARA signature and gets scrubbed worldwide in hours. The loader, though, is a *reusable delivery vehicle*: same code, new keys, re-staged GIFs, and every sample hashes differently, prints a different memory footprint, and defeats signature-first defense at every stage.

Building a loader that is "boring at every zoom level" — self-contained, layered, timing-randomized, hook-immune — is the difference between a one-shot op and an on-market platform. That's the whole game. And the defense that actually wins is the one that stopped watching for *malformed files* and started watching for *abnormal behavior at the kernel boundary*.

---

*This writeup is provided for defensive education and research. Rebuilding or re-deploying the techniques described here against systems you do not own or without authorization is illegal in most jurisdictions. Use this analysis to sharpen detection, not to arm attacks.*

# Module Stomping Execution Technique – Technical Writeup

### Overview

***Module stomping*** is a code execution technique that overwrites the ```.text``` (executable code) section of a legitimate, already-loaded module (DLL) with a malicious payload. Because the memory is image-backed and originally ```RX``` (Read-Execute), it avoids common EDR heuristics that flag private ```RWX``` allocations or syscall‑return‑into‑RWX patterns. This loader implements stomping as its sole execution path.

## How Module Stomping Works:

1. Identify a candidate module
The loader scans a predefined list of system DLLs that are typically loaded in most processes and have a ```.text``` section large enough to hold the payload. Candidates include:
1. ```propsys.dll```

2. ```uxtheme.dll```

3. ```version.dll```

4. ```userenv.dll```

5. ```dbghelp.dll```

6. ```winmm.dll```

For each module, it calls ```GetModuleHandleA``` (or ```LoadLibraryA``` if not yet loaded) and inspects the PE headers to locate the ```.text``` section and its virtual size.

2. Check size and prepare the target:
The payload (after prepending a jump‑over‑junk and obfuscation) must be smaller than the ```.text``` section’s virtual size. If a suitable module is found, the loader saves the original bytes of the target region (for later restoration).
3. Make the ```.text``` writable: ```VirtualProtect``` is called with ```PAGE_EXECUTE_READWRITE``` to allow overwriting the code.
4. Write and decrypt the payload: The obfuscated payload (already XOR‑encrypted) is copied into the ```.text``` region. Then it is decrypted in place using the same XOR key, producing plaintext shellcode. ```FlushInstructionCache``` ensures the CPU sees the new code.
5. Optional ```Ekko‑style``` sleep mask: Before execution, the loader can apply a sleep mask (RC4 encryption) to the ```.text``` region, sleep for a configurable dwell period, then decrypt it back. This hides the payload from memory scanners during the dwell.
6. Execute and restore: The ```.text``` region is set back to ```PAGE_EXECUTE_READ (RX)``` to maintain normal module protection. Execution jumps to the start of the payload. After the payload returns (if ever), the original bytes are restored, and the module’s integrity is re‑established.

---

## Why Use Module Stomping?
***Evades memory‑based detection*** – The payload resides in an image‑backed memory region that is already part of a signed DLL, not a private allocation with RWX or ```PAGE_EXECUTE_READWRITE``` that would trigger heuristic alerts.

***Bypasses NtAllocateVirtualMemory hooks**** – No direct syscall for allocation is needed; the payload is placed into existing memory.

***Low telemetry footprint*** – Overwriting a rarely‑used DLL’s ```.text``` may go unnoticed, especially if the original bytes are restored after execution.

---

## Limitations

***Payload size*** – The technique is only practical for small‑to‑medium payloads (typically < 1 MB) because system DLL ```.text``` sections are limited. Large payloads (e.g., 37 MB) will fail to find a candidate module.

***Module availability*** – Not all processes load the candidate DLLs; the loader may need to LoadLibrary them, which can be logged.

***Restoration*** – If the payload does not return, the original bytes are not restored, potentially causing instability. This is acceptable for one‑shot execution.

## Implementation Details in nutshell

The loader’s stomp routine is contained in execute_via_stomp(). It performs:

    ***Candidate loop*** – Iterates through the list, calls ```find_module_text()``` to get the ```.text``` start and size.

    ***Backup and overwrite*** – Saves original bytes, ```VirtualProtect``` to RWX, writes obfuscated payload, decrypts.

    ***Sleep mask*** – Optionally calls ```sleep_masked()``` (RC4 encryption + SleepEx + decryption).

    ***Execution*** – Casts the ```.text``` pointer to a function and calls it.

    ***Restore*** – Re‑writes original bytes and flushes cache.

The outer loader stages (GIF extraction, AES‑CBC decryption, XOR obfuscation, jump‑over‑junk) are identical to the other variants and are described in the main topic named: ***A Technical Breakdown of a Direct-Syscall APC Loader***

# Vectored Exception Handler (VEH) Trampoline – Technical Writeup

The VEH trampoline technique leverages Windows’ structured exception handling to redirect execution. A tiny ```ud2``` (illegal instruction) is placed in executable memory; when executed, it raises ```EXCEPTION_ILLEGAL_INSTRUCTION```. A vectored exception handler (registered with ```AddVectoredExceptionHandler```) catches this exception and modifies the context record to set RIP (or ```EIP```) to the payload’s address, then resumes execution. This bypasses common execution‑flow monitoring because no explicit ```call``` or ``jmp``` is used – control is transferred via the kernel’s exception dispatcher.

## Execution Flow

1. ***Staging*** – The loader extracts encrypted payload fragments from ```.gif``` comment sections, then decrypts them using AES‑CBC (two layers) and XOR scrambling.

2. ***Obfuscation*** – The decrypted shellcode is prepended with a short jump over random junk bytes, then XOR‑encrypted with a random 1‑ or 4‑byte key.

3 ***Allocation*** – A custom syscall trampoline is built (extracting the SSN for ```NtAllocateVirtualMemory``` from ntdll) to allocate an RWX memory region of the required size without calling the hooked ```VirtualAlloc``` API.

4. ***Write & decrypt*** – The obfuscated payload is copied into the allocated region, then decrypted in place to plaintext shellcode.

5. ***Ekko‑style sleep mask***  – The plaintext region is RC4‑encrypted, the thread sleeps for a configurable dwell (default 5 s) using ```SleepEx(TRUE)``` to remain alertable, then decrypted back. This hides the payload from memory scanners during the dwell.

6. ***VEH execution*** – A two‑byte ud2 trampoline is allocated, and the VEH handler is installed with AddVectoredExceptionHandler(1, ...). The trampoline is called, the handler redirects RIP to the payload, and execution continues inside the RWX region.

7. ***Cleanup*** – After the payload returns (if ever), the VEH handler is removed and the trampoline freed.

---

## Why VEH?

***No thread creation or APC*** – avoids kernel‑mode callbacks that are often monitored.

***Unconventional control flow*** – the exception dispatcher is not typically hooked by EDRs that focus on ```call/jmp``` or syscall sequences.

***Works for any payload size*** – the RWX allocation is private and can be as large as needed.

***Self‑contained***– all code runs in the current process; no remote injection.

---

## Limitations

***Exception visibility*** – The ```ud2``` exception may be logged by some EDRs as a suspicious crash attempt, though it is a first‑chance exception and often ignored.

***Reliance on VEH*** – Some security products monitor vectored exception handler registration. However, the handler is only active briefly.

---


# Timer‑Callback Execution – Technical Writeup

***Timer‑callback execution*** is a code‑execution technique that leverages Windows’ timer‑queue infrastructure (```CreateTimerQueueTimer```) to invoke a payload in a worker thread. Instead of explicitly calling ```CreateThread``` or queuing an APC, the loader registers a callback routine that receives the payload address as its parameter. When the timer fires (immediately or after a delay), the thread‑pool worker calls the callback, which then transfers control to the shellcode. This technique is stealthy because timer‑queue callbacks are rarely monitored by EDRs, and the execution flow originates from a legitimate system thread‑pool mechanism.


---

## How Timer‑Callback Execution Works

1. ***Staging*** – The loader extracts, decrypts, and obfuscates the payload from embedded GIF comments (using AES‑CBC + XOR same as before) .

2. ***Memory allocation*** – A private RWX region is allocated via a direct syscall (```NtAllocateVirtualMemory```) to avoid API hooks.

3. ***Payload preparation*** – The obfuscated payload is copied into the region, decrypted in place, and optionally protected with an Ekko‑style sleep mask (RC4 + dwell).

4. ***Timer creation*** – ```CreateTimerQueueTimer``` is called with:

    A callback function (```timer_callback```) that is a plain wrapper.

    The payload address passed as ```lpParam```.

    ```DueTime = 0 (fires immediately) and Period = 0 (one‑shot).```

5. ***Callback execution*** – The timer queue worker thread invokes ```timer_callback```, which casts the parameter to a function pointer and jumps to it. The payload runs in a separate thread belonging to the system’s thread pool.

6. ***Process keep‑alive*** – The main loader thread enters an infinite sleep loop, ensuring the process remains alive so the worker thread can execute.

---

# Unhooking – Restoring ntdll Prologues from Disk

***Unhooking*** is a defensive evasion technique that restores the original, unmodified code of Windows API functions inside the current process. Security products (EDRs, AVs) often place user‑mode hooks in the prologues of system DLLs – especially ntdll.dll – to monitor API calls. By overwriting these hooks with the original bytes from a clean copy of the DLL (read from disk or from KnownDlls), the loader can call native APIs without triggering inspection, making subsequent actions harder to detect.


## Why we love Unhooking?

    ***Bypass EDR callbacks*** – Hooks in ntdll can intercept every syscall. Restoring the original code removes these interceptors.

    ***Enable direct syscalls*** – Even if you use direct syscalls, some EDRs hook the syscall stub itself. Unhooking restores the original stub, so you can execute syscalls without being logged.

    ***Reduce telemetry*** – Without hooks, API calls appear as normal system activity, not flagged as suspicious.



## How It Works (Step‑by‑Step)

1. Obtain a clean copy of ```ntdll.dll```

    The loader opens ```C:\Windows\System32\ntdll.dll``` from disk (or uses the KnownDlls section) with ```CreateFile```, maps it into memory as read‑only via ```CreateFileMapping + MapViewOfFile```.

    This disk image is the original, unpatched version (unless Windows itself is compromised).

2. Locate the in‑memory ntdll base

    ***GetModuleHandleA("ntdll.dll")*** returns the base address of the loaded module in the current process.

3. Parse the PE headers

    Both disk and memory images have the same PE layout. The loader reads the DOS header, NT headers, and section headers from the disk image.

    It locates the export directory (EAT) by looking at the ```IMAGE_DIRECTORY_ENTRY_EXPORT``` in the Optional Header’s DataDirectory array.

4. Iterate exported functions (especially Nt* syscalls)

    The export directory contains arrays of names, ordinals, and function RVAs.

    The loader loops through all exported names.

    It filters for functions starting with "Nt" (e.g., NtAllocateVirtualMemory, NtCreateThreadEx). These are the primary targets of EDR hooks.

5. Calculate the function address in the current process

    The RVA (relative virtual address) of each function is obtained from the export table.

    The in‑memory address is ntdll_base + RVA.

6. Map the function’s RVA to a disk file offset

    Since the disk image is not loaded at its preferred base, the loader must convert the RVA to a file offset by walking the section headers:

        Find which section contains the RVA (based on VirtualAddress and VirtualSize).

        Compute ```disk_offset = RVA - section.VirtualAddress + section.PointerToRawData```.

7. Read the original prologue from the disk image

    At that disk offset, the loader reads the first 32 bytes (or enough to cover the typical hook, which is often 5–16 bytes).

    This memory contains the clean, unhooked instructions.

8. Overwrite the hooked prologue in the running process

    The loader calls VirtualProtect on the target address with PAGE_EXECUTE_READWRITE to make it writable.

    It copies the original bytes from the disk image over the first 32 bytes of the in‑memory function.

    It then restores the original protection and flushes the instruction cache (FlushInstructionCache) to ensure the CPU uses the new code.

9. Repeat for all Nt* functions – The loader patches every syscall stub, effectively removing all user‑mode hooks placed by the EDR.

***No permanent modification – The patch is applied in‑memory only; the disk file remains untouched. After the process exits, the hooks are gone automatically.***


## Limitations & Detection Risks

***Memory integrity checks*** – Some EDRs and Windows Defender (with HVCI/Code Integrity) protect system DLLs from being modified, even in user mode. VirtualProtect may fail with ERROR_ACCESS_DENIED.

***PatchGuard*** – Only affects kernel mode; user‑mode hooks can still be overwritten (unless protected by Windows Defender Application Control).

***Timing*** – If the EDR re‑hooks after the loader unhooks, the technique fails. In practice, this is rare because re‑hooking would require resetting page permissions and writing again, which is detectable.

***IAT hooks*** – Unhooking only removes inline hooks in the DLL’s code section. It does not fix Import Address Table (IAT) hooks, though those are less common in modern EDRs.

***Detection by EDR*** – The act of writing to ntdll’s .text section is suspicious; some EDRs monitor VirtualProtect calls on system DLLs. To reduce risk, the loader can use direct syscalls to perform the write (though the current implementation uses VirtualProtect from the unhooked ntdll – a chicken‑and‑egg problem).


---

# DLL Re‑mapping / Manual Mapping

DLL re‑mapping (also known as manual mapping) is the most robust user‑mode evasion technique. It loads a clean, unmodified copy of ntdll.dll directly from disk into the process memory, performs full PE relocations and import resolution, and then uses that copy exclusively for syscall stubs. Unlike unhooking (which overwrites the existing in‑memory ntdll), manual mapping does not modify the original system DLL’s .text section – avoiding memory‑write detections entirely. All subsequent API calls go through the freshly mapped clean image, which is completely free of EDR hooks.

### How It Works (Step‑by‑Step)

### 1. Obtain a clean copy of ntdll.dll from disk

- The loader opens `C:\Windows\System32\ntdll.dll` with `CreateFile`.
- A file mapping is created (`CreateFileMapping`) and the file is mapped into memory as read-only (`MapViewOfFile`).
- This ensures the disk image is untouched and not subject to in-memory patches.

### 2. Allocate a new executable region

- `VirtualAlloc` is called with `MEM_COMMIT | MEM_RESERVE` and `PAGE_EXECUTE_READWRITE`.
- The size is taken from `nt->OptionalHeader.SizeOfImage` – enough to hold the entire PE image.

### 3. Copy PE headers and sections

- The DOS and NT headers are copied first (`SizeOfHeaders` bytes).
- For each section (`.text`, `.data`, `.rdata`, etc.), the raw data is copied from the disk image to the corresponding virtual address in the new region.

### 4. Apply base relocations

- The loader parses the relocation table (`.reloc` section).
- It calculates `delta = newBase - ImageBase`.
- For each relocation entry with type `IMAGE_REL_BASED_DIR64` (x64), it adds the delta to the absolute address at the patch location.
- This ensures all absolute addresses (e.g., global variables, function pointers) point to the correct new location.

### 5. Resolve imports

- The loader iterates the import directory.
- For each imported DLL (e.g., `kernel32.dll`, `ws2_32.dll`), it gets the module handle via `GetModuleHandleA` (or loads it with `LoadLibraryA`).
- For each imported function, it resolves the address with `GetProcAddress` and writes it into the Import Address Table (IAT) of the new image.
- **Note:** While imports are resolved, the loader only needs the syscall stubs from ntdll – the rest of the image is filled for completeness and to avoid crashes if the image is used for other purposes.

### 6. Flush the instruction cache

- `FlushInstructionCache` ensures the CPU sees the newly written code, preventing stale cache issues.

### 7. Build syscall stubs from the clean copy

- Instead of calling `GetProcAddress` on the system ntdll, the loader scans the export directory of the newly mapped image.
- For functions like `NtAllocateVirtualMemory`, it extracts the function address directly from the clean copy.
- A custom syscall stub is then built using the SSN (Syscall Number) extracted from that clean function’s prologue.
- This stub is placed in an executable region and used as the API entry point.

### 8. Perform injection via clean syscalls

- The payload is decrypted, obfuscated, and allocated with the clean `NtAllocateVirtualMemory`.
- All API calls made by the loader now go through the clean ntdll copy, bypassing any hooks in the system-loaded version.

---

### Mapping the Clean DLL

```c
void *MapCleanNtdll(void) {
    // 1. Open and map ntdll.dll from disk
    // 2. Parse PE headers
    // 3. Allocate new memory
    // 4. Copy headers + sections
    // 5. Apply relocations
    // 6. Resolve imports
    // 7. Return new base address
}
```

### Building the Syscall Stub

```c
static void *build_syscall_stub_with_random(const char *func_name, void *clean_ntdll) {
    // 1. Locate function in clean ntdll's export table
    // 2. Read prologue to extract SSN
    // 3. Build custom stub: mov eax, SSN; mov r10, rcx; syscall; ret
    // 4. Allocate and return executable stub
}
```

### Using the Clean Copy

```c
void *cleanNtdll = MapCleanNtdll();
if (!cleanNtdll) return 0; // No fallback – pure remapping

void *alloc_stub = build_syscall_stub_with_random("NtAllocateVirtualMemory", cleanNtdll);
NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)alloc_stub;
NtAllocateVirtualMemory(process, &remote, ...); // Unhooked syscall
```

---

## Integration with Threadless Injection

The loader combines remapping with threadless injection (CreateThreadpoolWork + SubmitThreadpoolWork):

    Map clean ntdll – obtains a hook‑free copy.

    Allocate payload – uses clean NtAllocateVirtualMemory.

    Obfuscate and sleep‑mask – applies Ekko‑style RC4 encryption + dwell.

    Submit threadpool work – queue the payload on an existing thread‑pool thread.

    Payload executes – on a system thread, with no new thread creation and no API hooks.


---

# Detection Risks

***Memory scanners*** may flag the new executable region as suspicious if it’s not a known module.

***ETW/AMSI*** may still catch the payload itself (obfuscation and sleep masking mitigate this).

***CFG/HVCI*** may block the allocation if strict code integrity is enforced.

<br>


# Technical Glossary — Direct-Syscall APC Loader / Module Stomping / VEH Trampoline Writeup

Plain-language explanations of the technical terms used in the document.  

---

## A

**AES-128-CBC**  
Advanced Encryption Standard with 128-bit keys in Cipher Block Chaining mode. Each block is XORed with the previous ciphertext block before encryption. Used here as one of the two encryption layers around the payload.

**Alertable wait**  
A wait state (e.g. `SleepEx` with the alertable flag set) that allows the kernel to deliver queued user-mode APCs to the thread.

**APC (Asynchronous Procedure Call)**  
A mechanism that queues a function to run in the context of a specific thread when that thread enters an alertable wait. Used for quiet self-execution without creating a new thread.

**API hooking / Inline hook**  
An EDR or security product overwrites the first few bytes of a legitimate Windows API function (usually in `ntdll.dll`) with a jump into its own monitoring code so it can inspect or block the call.

---

## B

**BCrypt**  
Windows Cryptography API: Next Generation (CNG) provider. The loader uses it for AES decryption on the Windows side.

**Blob**  
The concatenated, still-encrypted payload data recovered from the GIF comment blocks.

**Builder**  
The offline tool that takes raw shellcode, applies the multi-layer encryption + scrambling, and produces the final container that the loader later decrypts.

---

## C

**CET (Control-flow Enforcement Technology)**  
Hardware feature (Intel/AMD) that uses a shadow stack and indirect branch tracking to make it harder for code to jump to unexpected addresses (e.g. trampolines on the heap).

**Comment Extension (GIF)**  
A GIF89a structure starting with `0x21 0xFE` that can hold arbitrary data. The payload fragments are hidden inside these blocks.

**Config Loader**  
A first-stage component whose only job is to recover, decrypt, and execute an encrypted payload. It is not the payload itself.

**ConvertThreadToFiber / CreateFiber / SwitchToFiber**  
Windows Fiber API. Turns the current thread into a fiber, creates a new fiber whose start address is the payload, then switches the CPU to that fiber. Pure user-mode stack switch — no new thread object and no APC.

---

## D

**Direct syscall**  
Issuing the `syscall` instruction yourself from a hand-built stub instead of calling the normal `ntdll` function. Bypasses user-mode API hooks placed by EDRs.

**Dummy / Decoy field**  
A header field or piece of code that looks important but is never used. Forces an analyst to waste time investigating it.

---

## E

**EDR**  
Endpoint Detection and Response product (CrowdStrike, SentinelOne, Defender, etc.).

**Ekko-style sleep mask**  
Technique that encrypts the payload in memory (often with RC4), sleeps for a period, then decrypts it again. Hides the plaintext from memory scanners during the dwell time.

**Entropy (Shannon)**  
A measure of randomness in a data block. High-entropy comment blocks inside GIFs are a strong indicator of encrypted payload staging.

**ETW (Event Tracing for Windows)**  
Windows kernel and user-mode event logging infrastructure. Kernel providers such as Threat-Intelligence can see syscalls and thread starts regardless of user-mode hooks.

---

## F

**Fiber**  
A lightweight, user-mode execution context with its own stack. Managed entirely by the Fiber API; it is not a thread and creates no kernel object.

**FlushInstructionCache**  
Forces the CPU to discard any cached instructions for a memory region so that freshly written code is visible to the instruction fetcher.

---

## G

**GIF89a**  
The Graphics Interchange Format version that supports Comment Extension blocks. Used as the benign carrier for the encrypted payload fragments.

---

## I

**Image-backed memory**  
Memory that belongs to a loaded PE module (DLL/EXE). EDRs treat it more leniently than private (anonymous) allocations.

**Inline hook**  
See API hooking.

---

## J

**Jump-over-junk / Polymorphic entry**  
A short relative jump (`EB <n>`) followed by random bytes prepended to the shellcode. Changes the entry-point bytes on every run so signatures keyed on the start of the payload fail.

---

## K

**Keep-alive thread**  
A background thread that periodically sleeps and does meaningless work so the process looks like a normal long-running daemon instead of a one-shot loader.

---

## L

**LCG (Linear Congruential Generator)**  
Simple PRNG of the form `state = state * a + c`. Used here only for cheap XOR scrambling between AES layers (not for real confidentiality).

**LOTL (Living Off The Land)**  
Using legitimate system components or existing files (here, GIFs inside `node_modules`) instead of dropping suspicious binaries.

---

## M

**Module stomping**  
Overwriting the `.text` (code) section of an already-loaded legitimate DLL with the payload. The memory remains image-backed and originally RX, avoiding many private-RWX heuristics.

**MITRE ATT&CK**  
Knowledge base of adversary tactics and techniques. The writeup maps each evasion to approximate technique IDs.

---

## N

**ntdll.dll**  
The lowest-level user-mode library that contains the actual syscall stubs for most Windows NT APIs.

**NtAllocateVirtualMemory / NtProtectVirtualMemory / NtCreateThreadEx**  
Native NT API functions that perform the real work behind VirtualAlloc, VirtualProtect, and thread creation. The loader builds its own trampolines for them.

**NOP sled**  
Sequence of no-operation instructions (`nop`) placed in front of a syscall stub. Random length breaks fixed-offset signatures.

---

## O

**Obfuscation vs Encryption**  
Obfuscation makes analysis harder (signatures, visual inspection). Encryption prevents reading the content without the key. The loader uses both, layered.

---

## P

**PAGE_EXECUTE_READ (RX)**  
Memory protection that allows reading and executing but not writing. Legitimate loaded modules use this.

**PAGE_EXECUTE_READWRITE (RWX)**  
Memory that is both writable and executable. Almost universally flagged by EDRs; the APC variant deliberately avoids it.

**PAGE_READWRITE (RW)**  
Writable but not executable. Used for the initial allocation before the final protect flip.

**PE (Portable Executable)**  
Windows executable format. The loader parses the on-disk `ntdll.dll` PE headers to recover syscall numbers when the in-memory copy is hooked.

**Private allocation**  
Memory obtained via VirtualAlloc / NtAllocateVirtualMemory that is not backed by a file or module. Easy for EDRs to flag when it is also executable.

**PRNG**  
Pseudo-Random Number Generator. Here an LCG used for scrambling and for runtime polymorphism (NOP counts, sleep lengths, keys).

---

## R

**RVA (Relative Virtual Address)**  
Offset from the base of a PE image. Converted to a file offset when parsing the on-disk DLL.

**RW → RX flip**  
Allocate writable, write ciphertext, decrypt in place, then change protection to execute-only. Avoids ever having a region that is both writable and executable at the same time.

---

## S

**Shellcode**  
Position-independent machine code that can run directly from memory without being a full PE.

**SSN (System Service Number)**  
The integer that tells the Windows kernel which system call is being requested. The only value a direct-syscall stub needs.

**Staging**  
Hiding the encrypted payload pieces inside benign files (GIF comment blocks scattered across `node_modules` folders).

**Stager**  
The Python script that splits the encrypted blob into 255-byte chunks and injects them into the comment blocks of visible GIFs.

**Syscall trampoline**  
A tiny, hand-built function that loads the SSN into `eax`, moves the first argument into `r10`, executes `syscall`, and returns. Replaces the normal `ntdll` stub.

---

## T

**TEB / TIB**  
Thread Environment Block / Thread Information Block. Fiber stacks are allocated differently from normal thread stacks; some shellcode that reads TEB data can break under pure fiber execution.

**Trampoline**  
See syscall trampoline. Also used for the small `mov rax, payload; jmp rax` stub queued as an APC.

---

## U

**ud2**  
x86/x64 illegal instruction. Used in the VEH technique to deliberately raise `EXCEPTION_ILLEGAL_INSTRUCTION` so a vectored handler can redirect execution.

---

## V

**VEH (Vectored Exception Handler)**  
A process-wide exception handler registered with `AddVectoredExceptionHandler`. The VEH trampoline technique places an illegal instruction, catches the resulting exception, and rewrites the instruction pointer to the payload.

**VirtualProtect / NtProtectVirtualMemory**  
Changes the protection flags of a memory region (e.g. RW → RX).

---

## W

**W+X / Never W+X**  
The policy of never allowing a memory region to be both writable and executable at the same time. The APC variant follows this; the fiber variant sometimes allocates RWX directly as a trade-off.

---

<br>

thank you for reading. have a good day or night or afternoon
<br>
cheers
