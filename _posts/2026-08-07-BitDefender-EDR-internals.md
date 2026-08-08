---
title: "documenting important drivers in bitdefender EDR antigravity zone, and analysing how it catches bad guys"
date: 2026-08-07 00:00:00 +0000
categories: [Red Team, EDR]
tags: [EDR, driver, opsec, Bitdefender]
description: "documenting important drivers in bitdefender EDR antigravity zone, and analysing how it catches bad guys"
toc: true
image:
  path: /assets/EDRbit.png
  alt: EDR internals
---

# Inside Bitdefender's Advanced Threat Control (`atc.sys`)

### A technical deep-dive into a production EDR kernel sensor: bootstrap, authenticated IPC, behavioral classification pipeline, WFP networking, and process termination

**Target:** `atc.sys`, version `v1.84.443.0` (build tag `0x00d8ca558`)
**Symbol source:** `C:\docker_src\atc\bin\x64\Release\atc\atc.pdb`
**Method:** Static reverse engineering (IDA Pro, x64, flat virtual addresses)
**Intended audience:** Security researchers, EDR/AV developers, kernel engineers, malware analysts, and threat-hunting teams

---

## Reading guide and evidence model

This document is written for readers who already know what a minifilter is and what `IRQL`
means. It still explains *why* the design choices matter, because that is where the real insight
lives.

Before anything else, one methodological point, stated once and honored throughout:

> **A string or an import in a driver is evidence of intent, not proof of behavior.**

When I write "ATC detects Heaven's Gate," the literal, verified claim is "the binary contains the
string `HeavenGate` inside its detection logic." Whether the technique is actually caught, how
reliably, and under what conditions is a question that static analysis alone cannot answer. To
keep the two apart, this document uses a strict vocabulary:

- **Observed** — present in the binary: a string, an import, a control-flow edge, a constant.
- **Recovered** — a control-flow structure (call tree, switch, loop) that we traced in IDA.
- **Inferred / likely** — an interpretation of observations based on how Windows works and how
  EDR products are built. These are labeled every time they appear.

Every address is a flat virtual address valid for this specific build (v1.84.443.0). Other builds
of `atc.sys` will have different addresses.

---

## Table of Contents

1. What ATC is and what this document covers
2. Build identity and what it leaks
3. The module ecosystem around the driver
4. Bootstrap and minifilter registration
5. The IPC architecture
   5.1. Why two ports?
   5.2. The port name (and why it's hidden)
   5.3. Connection attestation — the handshake
   5.4. The message dispatcher and command surface
   5.5. The outbound path and `FltSendMessage`
6. The behavioral detection pipeline
   6.1. Event classification
   6.2. The behavior switch
   6.3. The suspicion engine
   6.4. Verdict and action model
7. Process termination
8. Detection surface
   8.1. Process, thread, and image monitoring
   8.2. Anti-evasion heuristics
   8.3. Interpreter hooking (Python, .NET, AMSI)
   8.4. WFP network sensor and in-kernel HTTP parsing
   8.5. Credential and logon telemetry
   8.6. Detection categories
9. Tamper defense
10. Telemetry and event serialization
11. Synthesis — how the pieces fit
12. Open questions and next steps
13. Appendices
    A. Key global symbols
    B. Observed strings (raw evidence)
    C. Key imports
    D. Glossary

---

## 1. What ATC is and what this document covers

**Advanced Threat Control (ATC)** is Bitdefender's behavioral detection engine. Classic signature
AV compares file hashes and byte patterns against a database of known malware. ATC takes a
different path: it watches what software **does** — creating processes, mapping images, writing to
other processes, connecting to the network, executing scripts — and judges whether the *behavior*
looks malicious. This is what lets behavioral engines catch zero-days and heavily obfuscated
families that no signature has been written for yet.

`atc.sys` is the **kernel-resident half** of that engine. It is the sensor that sits closest to
the operating system and sees events the moment they happen.

What this document reconstructs, from static analysis:

- How the driver registers with the OS and what event surface it subscribes to.
- How it communicates with its user-mode partner — two Filter Manager communication ports, a
  cryptographic handshake, per-session cookies, and a serialized command dispatcher.
- How the detection pipeline is structured: classify → route → score → validate → act.
- How termination is executed in kernel mode.
- The breadth of its sensors: process/thread/image monitoring, an anti-evasion catalog, an
  interpreter hooking layer, a full WFP network sensor with an in-kernel HTTP parser, credential
  and logon telemetry, and anti-tamper machinery.

---

## 2. Build identity and what it leaks

The binary identifies itself clearly:

```
Version string :  v1.84.443.0 0x00d8ca558
PDB path       :  C:\docker_src\atc\bin\x64\Release\atc\atc.pdb
```

![ATC version](/assets/Build.png)

Three separate facts come out of these two lines, each worth understanding:

1. **Version scheme.** `1.84.443.0` is the semantic version. `0x00d8ca558` is a build identifier
   embedded alongside it. Together they let you fingerprint the exact build — useful if you ever
   need to compare driver behavior across product updates.

2. **Build topology leak.** The PDB path is `C:\docker_src\atc\bin\x64\Release\atc\atc.pdb`.
   That tells us the build was produced in a Docker-based build environment (`docker_src`), in an
   `x64 Release` configuration, from a source tree with a top-level `atc` directory. The PDB
   was **not stripped** before shipping. For analysis, an unstripped PDB is gold: if it were
   published, you'd have full symbol names. We only have the *path*, so we work from the binary's
   flat names instead.

3. **A private section: `.atcsec`.** The binary contains a custom section named `.atcsec`.
   Custom sections are a deliberate layout choice. Common reasons: isolating
   self-protection/validation code so it occupies a dedicated mapped region, or preparing a
   contiguous region that something else (e.g., a loader or an integrity check) expects. Exactly
   what `.atcsec` protects is not resolved in this pass, but its presence is a fact worth
   recording — it is part of how the driver takes care of its own integrity.

---

## 3. The module ecosystem around the driver

The version descriptor block references sibling components the driver coordinates with:

| Module | Reading of the name |
|--------|---------------------|
| `atcuf32.dll` / `atcuf64.dll` | "ATC **u**ser-mode **f**rontend" — the local user-mode client |
| `bdhkm32.dll` / `bdhkm64.dll` | "Bitdefender **k**ernel-**m**emory/hook" — a hooking component |
| `AtcCoreVersion`, `AtcufVersion`, `BdhkmVersion`, `DpiVersion` | Version bookkeeping |

The naming is informative:

- **`atcuf`** — the user-mode frontend — is the process-side half of the ATC sensor. Everything
  the kernel reports is handed to this component.
- **`bdhkm`** — the kernel-memory/hook component — is what the "bitdefender kernel-mode"
  ecosystem injects to observe and sometimes hook process memory and API behavior.
- **`DpiVersion`** — "deep packet inspection" — corroborates the WFP/network portion of the
  driver we describe in §8.4.

A practical consequence for live analysis: **the process that loads `atcuf64.dll` is the process
that owns the ATC communication port.** If you want to observe ATC IPC traffic in real time, that
is the process to instrument.

---

## 4. Bootstrap and minifilter registration

### 4.1 The entry path

```
DriverEntry
   -> sub_1405F5540        ; driver-scope state construction
      -> sub_1405EECE0     ; filter instance creation
         -> FltRegisterFilter
              registration struct at 0x1407C2870
              filter GUID {045D888A-EB1C-11C9-9FE8-08002B104860}
```

![ATC version](/assets/mini.png)
![ATC version](/assets/ini2.png)

`DriverEntry` hands off quickly. `sub_1405F5540` builds driver-level state (globals, locks,
worker objects). `sub_1405EECE0` constructs the filter instance and calls
`FltRegisterFilter` with a registration structure at `0x1407C2870` — the structure that enumerates
every callback the driver installs.

The filter has a **stable GUID**: `{045D888A-EB1C-11C9-9FE8-08002B104860}`. GUIDs in minifilter
registration are the product's permanent fingerprint. You can confirm a live instance with:

```
fltmc instances -v        ; lists minifilter instances and their altitude
!fltkd.filters            ; from the kernel debugger
```

### 4.2 What registration means, technically

Registering as a minifilter means the driver plugs into the Filter Manager's I/O model. The
Filter Manager interposes the driver between the I/O manager and the file system stack, invoking
the driver's callbacks (`PreOperation`, `PostOperation`, and port callbacks) on I/O that matches
the driver's registered operation set.

Two implications matter for an ATC-class driver:

- **Altitude/ordering.** Minifilters run in a defined order. A behavioral engine wants to see I/O
  early in the pipeline so it can both observe and, if needed, veto operations before they reach
  the file system.
- **IRQL and context.** Minifilter callbacks run at `APC_LEVEL` or lower for pre/post operations.
  This constrains what the callbacks can do — which is exactly why the kill path is deferred to a
  worker thread (see §7). Heavy work cannot happen inline in a callback.

Because ATC's signal is behavioral, the driver leans on broad pre-operation coverage and routes
everything into a heuristic pipeline rather than doing inline byte-pattern matching on buffers.
That architectural choice — "collect and judge" instead of "match and drop" — is visible
throughout the code.

---

## 5. The IPC architecture

### 5.1 Why two ports?

`atc.sys` publishes **two** Filter Manager communication ports:

| Port | Registration site | Role (observed) |
|------|-------------------|-----------------|
| Port A | `sub_14032AB00` | Control / notification plane |
| Port B | `sub_140227DE0` | Primary control channel |

![tow ports](/assets/tow.png)

Both are created with `MaxConnections = 1`, so each accepts a single connected client. Splitting
control into two ports is a common EDR pattern:

- One channel carries **notifications** (events flowing kernel → user mode).
- The other carries **control** (configuration, queries, commands flowing user → kernel).

Splitting them lets the driver serve high-frequency telemetry and low-frequency control without
one blocking the other, and gives the driver two independent backchannels with independent state.

A security descriptor is built via `FltBuildDefaultSecurityDescriptor`, so the port is
protected at the object level. But — and this is the important part — the descriptor is **not**
the real gate. The driver runs its own attestation at connection time (§5.3).

### 5.2 The port name (and why it's hidden)

Normally a driver exposes its communication port path as a static wide string, e.g.
`\Bitdefender\AtcPort`. Here the port name is **assembled at runtime** into a data buffer
(`byte_1408B42C0`) rather than baked into `.rdata`.

![tow ports](/assets/towme.png)

Why does this matter? Because the port path is the handle that lets user-mode processes find the
driver. A runtime-built name means:

- a plain `strings` pass over the driver reveals no port path;
- the name may be derived from version data, a random seed, or machine state — which would make
  it differ per install or per boot.

We investigated one promising builder, `sub_1401E617C`, and it turned out to be a trivial
accessor — `mov rax, [rcx+10h]; retn` — i.e. a C++ field getter, not the name constructor. The
real builder is still unlocated. This is recorded honestly in §12 rather than papered over.

![tow ports](/assets/builder.png)

### 5.3 Connection attestation — the handshake

```C
__int64 __fastcall ConnectNotifyCallback(
        PFLT_PORT ClientPort,
        PVOID ServerPortCookie,
        unsigned __int16 *ConnectionContext,
        ULONG SizeOfContext,
        PVOID *ConnectionPortCookie)
{
  __int64 v5; // rdi
  PVOID *v8; // rdx
  __int64 result; // rax
  PDEVICE_OBJECT v10; // rcx
  __int64 v11; // rdx
  __int64 v12; // r9
  int v13; // edi
  int v14; // r9d
  __int64 i; // rdx
  int v16; // eax
  __int64 v17; // rdx
  NTSTATUS v18; // eax
  void *v19; // rax
  struct _TIME_FIELDS *v20; // [rsp+20h] [rbp-148h]
  unsigned int v21; // [rsp+50h] [rbp-118h]
  int v22; // [rsp+50h] [rbp-118h]
  __int128 v24; // [rsp+70h] [rbp-F8h]
  __int128 v25; // [rsp+80h] [rbp-E8h] BYREF
  __int64 v26; // [rsp+90h] [rbp-D8h] BYREF
  __int64 v27; // [rsp+98h] [rbp-D0h] BYREF
  __int128 v28; // [rsp+A0h] [rbp-C8h] BYREF
  _BYTE v29[16]; // [rsp+B0h] [rbp-B8h] BYREF
  _BYTE v30[112]; // [rsp+C0h] [rbp-A8h] BYREF
  _QWORD v31[2]; // [rsp+130h] [rbp-38h] BYREF

  v5 = SizeOfContext;
  v8 = ConnectionPortCookie;
  v27 = 0;
  v28 = 0;
  v26 = 0;
  *(_OWORD *)v31 = 0;
  if ( DeviceObject != (PDEVICE_OBJECT)&DeviceObject
    && (HIDWORD(DeviceObject->Timer) & 0x40) != 0
    && BYTE1(DeviceObject->Timer) >= 5u )
  {
    sub_140034D40(a1: DeviceObject->AttachedDevice, a2: 92, a3: &unk_1407AF870, a4: ClientPort);
    v8 = ConnectionPortCookie;
  }
  if ( ClientPort == nullptr )
  {
    if ( DeviceObject != (PDEVICE_OBJECT)&DeviceObject
      && (HIDWORD(DeviceObject->Timer) & 0x40) != 0
      && BYTE1(DeviceObject->Timer) >= 2u )
    {
      sub_14002AD40(a1: DeviceObject->AttachedDevice, a2: 93, a3: &unk_1407AF870, a4: 3221225711LL);
    }
    return 3221225711LL;
  }
  if ( ConnectionContext == nullptr || (unsigned int)v5 < 0x30 )
  {
    v10 = DeviceObject;
    if ( DeviceObject == (PDEVICE_OBJECT)&DeviceObject
      || (HIDWORD(DeviceObject->Timer) & 0x40) == 0
      || BYTE1(DeviceObject->Timer) < 2u )
    {
      return 3221225506LL;
    }
    v11 = 94;
LABEL_96:
    v12 = 3221225713LL;
LABEL_97:
    sub_14002AD40(a1: v10->AttachedDevice, a2: v11, a3: &unk_1407AF870, a4: v12);
    return 3221225506LL;
  }
  *((_DWORD *)ConnectionContext + 6) = -1073741823;
  if ( v5 - 48 < (unsigned __int64)ConnectionContext[22] )
  {
    v10 = DeviceObject;
    if ( DeviceObject == (PDEVICE_OBJECT)&DeviceObject
      || (HIDWORD(DeviceObject->Timer) & 0x40) == 0
      || BYTE1(DeviceObject->Timer) < 2u )
    {
      return 3221225506LL;
    }
    v11 = 95;
    goto LABEL_96;
  }
  if ( v8 == nullptr )
  {
    v10 = DeviceObject;
    if ( DeviceObject == (PDEVICE_OBJECT)&DeviceObject
      || (HIDWORD(DeviceObject->Timer) & 0x40) == 0
      || BYTE1(DeviceObject->Timer) < 2u )
    {
      return 3221225506LL;
    }
    v11 = 96;
    v12 = 3221225715LL;
    goto LABEL_97;
  }
  FltAcquirePushLockExclusive(PushLock: &qword_1408B4320);
  if ( byte_1408B4328 == 0 )
  {
    v13 = -402391036;
    goto LABEL_25;
  }
  if ( (unsigned __int8)sub_14002E454(a1: ConnectionContext) == 0 )
  {
    v13 = -402391032;
    v21 = -402391032;
    if ( DeviceObject != (PDEVICE_OBJECT)&DeviceObject
      && (HIDWORD(DeviceObject->Timer) & 0x40) != 0
      && BYTE1(DeviceObject->Timer) != 0 )
    {
      sub_140234A1C(
        a1: DeviceObject->AttachedDevice,
        a2: 97,
        a3: &unk_1407AF870,
        a4: 0,
        a5: 83,
        a6: 0,
        a7: *(_DWORD *)ConnectionContext,
        a8: *((_DWORD *)ConnectionContext + 1),
        a9: *((_DWORD *)ConnectionContext + 2));
    }
    goto LABEL_55;
  }
  LODWORD(stru_1408B1D20.Dpc.DeferredContext) = *((_DWORD *)ConnectionContext + 2);
  stru_1408B1D20.Dpc.DeferredRoutine = *(PKDEFERRED_ROUTINE *)ConnectionContext;
  stru_1408B1D20.Dpc.SystemArgument1 = *((PVOID *)ConnectionContext + 2);
  WORD1(v28) = ConnectionContext[22];
  LOWORD(v28) = WORD1(v28);
  *((_QWORD *)&v28 + 1) = ConnectionContext + 23;
  if ( (int)sub_1402419A0(a1: &qword_1408B3AA0, a2: 1, a3: &v28) >= 0 )
  {
    v13 = sub_14023E340(a1: &qword_1408B3AA0);
    v21 = v13;
    if ( v13 < 0 )
      goto LABEL_55;
    v13 = sub_140240500(a1: &qword_1408B3AA0, a2: &v27);
    v21 = v13;
    if ( v13 < 0 )
      goto LABEL_55;
    sub_14060A4E4(a1: v30);
    sub_14060A520(a1: v30, a2: ConnectionContext + 14, a3: 16);
    sub_14060A3C0(a1: v30);
    for ( i = 0; (unsigned int)i < 0x10; i = (unsigned int)(i + 1) )
      *((_BYTE *)v31 + i) = v30[i + 88];
    memset(v30, 0, 0x68u);
    v13 = sub_14044F1E0(a1: (int)v31, a2: v27, a3: (int)&v26, a4: v14, TimeFields: v20);
    v21 = v13;
    if ( v13 < 0 )
      goto LABEL_55;
    v16 = sub_1404638E0(a1: v26);
    v13 = v16;
    v21 = v16;
    if ( v16 < 0 )
    {
      if ( DeviceObject != (PDEVICE_OBJECT)&DeviceObject
        && (HIDWORD(DeviceObject->Timer) & 1) != 0
        && BYTE1(DeviceObject->Timer) >= 2u )
      {
        _mm_lfence();
        v13 = v16;
        sub_14002AD40(a1: DeviceObject->AttachedDevice, a2: 98, a3: &unk_1407AF870, a4: (unsigned int)v16);
      }
      goto LABEL_55;
    }
    sub_14046377C(a1: v26);
    v22 = sub_14037C5C0(a1: &unk_1408B42B0);
    if ( v22 < 0
      && DeviceObject != (PDEVICE_OBJECT)&DeviceObject
      && (HIDWORD(DeviceObject->Timer) & 0x40) != 0
      && BYTE1(DeviceObject->Timer) != 0 )
    {
      _mm_lfence();
      sub_14002AD40(a1: DeviceObject->AttachedDevice, a2: 99, a3: &unk_1407AF870, a4: (unsigned int)v22);
    }
    v29[0] = 0;
    sub_140490960(a1: v26, a2: v29);
    sub_140239E60(a1: &qword_1408B5A78, a2: v26, a3: v29);
    xmmword_1408B3C78 = *(_OWORD *)v31;
    if ( DeviceObject != (PDEVICE_OBJECT)&DeviceObject
      && (HIDWORD(DeviceObject->Timer) & 0x40) != 0
      && BYTE1(DeviceObject->Timer) >= 4u )
    {
      *((_QWORD *)&v24 + 1) = 16;
      *(_QWORD *)&v24 = v31;
      v25 = v24;
      sub_1401477A0(a1: DeviceObject->AttachedDevice, a2: 100, a3: &unk_1407AF870, a4: &v25);
    }
    LOBYTE(v17) = 1;
    sub_14025ACC0(a1: &unk_1408B5A80, a2: v17);
    sub_14025A900();
    sub_1401736A0(a1: &qword_1408B6078);
    v13 = 0;
  }
  else
  {
    v13 = -402390974;
  }
  v21 = v13;
LABEL_55:
  if ( v13 < 0 )
    goto LABEL_68;
  if ( ::ClientPort != nullptr )
  {
    v13 = -402391037;
  }
  else
  {
    qword_1408B4338 = (__int64)PsGetCurrentProcessId();
    v18 = PsLookupProcessByProcessId(ProcessId: (HANDLE)qword_1408B4338, Process: &Process);
    v13 = v18;
    v21 = v18;
    if ( v18 < 0 )
    {
      if ( DeviceObject != (PDEVICE_OBJECT)&DeviceObject
        && (HIDWORD(DeviceObject->Timer) & 0x40) != 0
        && BYTE1(DeviceObject->Timer) >= 2u )
      {
        _mm_lfence();
        v13 = v18;
        sub_14002AD40(a1: DeviceObject->AttachedDevice, a2: 101, a3: &unk_1407AF870, a4: (unsigned int)v18);
      }
      goto LABEL_68;
    }
    ::ClientPort = ClientPort;
    v19 = (void *)sub_14044F0E0(a1: ConnectionContext + 14);
    *ConnectionPortCookie = v19;
    qword_1408B3C98 = (__int64)v19;
    if ( DeviceObject != (PDEVICE_OBJECT)&DeviceObject
      && (HIDWORD(DeviceObject->Timer) & 0x40) != 0
      && BYTE1(DeviceObject->Timer) >= 4u )
    {
      sub_140234900(
        a1: DeviceObject->AttachedDevice,
        a2: 102,
        a3: (unsigned int)&unk_1407AF870,
        a4: qword_1408B4338,
        a5: qword_1408B4338,
        a6: (__int64)*ConnectionPortCookie);
    }
    _InterlockedExchange(&dword_1408B3C90, 1);
    v13 = 0;
  }
LABEL_25:
  v21 = v13;
LABEL_68:
  if ( v26 != 0 )
    sub_1404637A0(a1: &v26);
  if ( v27 != 0 )
    sub_140463840(a1: &v27);
  *((_DWORD *)ConnectionContext + 6) = v13;
  if ( v13 < 0 && Process != nullptr )
  {
    ObfDereferenceObject(Object: Process);
    Process = nullptr;
  }
  FltReleasePushLock(PushLock: &qword_1408B4320);
  if ( v13 >= 0 )
  {
    if ( DeviceObject != (PDEVICE_OBJECT)&DeviceObject
      && (HIDWORD(DeviceObject->Timer) & 0x40) != 0
      && BYTE1(DeviceObject->Timer) >= 4u )
    {
      _mm_lfence();
      sub_14002AD40(a1: DeviceObject->AttachedDevice, a2: 104, a3: &unk_1407AF870, a4: v21);
    }
    return 0;
  }
  else
  {
    if ( DeviceObject != (PDEVICE_OBJECT)&DeviceObject
      && (HIDWORD(DeviceObject->Timer) & 0x40) != 0
      && BYTE1(DeviceObject->Timer) >= 2u )
    {
      _mm_lfence();
      v13 = v21;
      sub_14002AD40(a1: DeviceObject->AttachedDevice, a2: 103, a3: &unk_1407AF870, a4: v21);
    }
    if ( v13 == -402390973 )
    {
      return 3221225730LL;
    }
    else if ( v13 == -402390964 )
    {
      return 3221225562LL;
    }
    else
    {
      result = 3221225875LL;
      if ( v13 != -402390963 )
        return 3221225506LL;
    }
  }
  return result;
}
```

When a user-mode client calls `FilterConnectCommunicationPort`, the Filter Manager invokes the
driver's `ConnectNotifyCallback` at `sub_1402281C0`. The recovered logic:


1. **Single-connection enforcement.** A guarded flag ensures one live connection. A second
   concurrent connect is rejected with status `0xE8040004`.
2. **Context buffer requirements.** The client must supply a connection context of at least
   `0x30` bytes, containing the client name and attestation material.
3. **Key check and cookie derivation.**
   - The client provides a **16-byte key** inside the context.
   - The driver hashes the key and compares it against a stored verification value.
   - On success, the driver derives a **per-connection cookie** (session nonce) and stores it in
     `qword_1408B3C98`.
4. **Identity recording.** The connecting process's PID and EPROCESS are stored
   (`qword_1408B4338` and `Process`).
5. **Global state transition.** The driver stores the connected ```ClientPort``` pointer globally and atomically sets ```dword_1408B3C90``` to 1 under a shared push lock. A small accessor later reads ```::ClientPort``` or ```dword_1408B3C90``` to answer 'is the client up?'"

```sub_140228154```  is an atomic state query getter.

It reads the current value of the global flag ```dword_1408B3C90``` in a thread-safe manner and returns whether that flag is set to 1.

How it works:

    _InterlockedCompareExchange(&dword_1408B3C90, 1, 1) attempts to exchange the value with 1 only if it is already 1.

    Since the exchange value and the comparand are identical, this operation never changes the variable—it simply reads the current value atomically and returns the original value.

    The function then checks if that returned original value equals 1.

What it returns:

    true → The driver has a valid, connected client (the handshake succeeded and the flag was set to 1 by the connection callback).

    false → No valid client is currently connected.

Its role in the driver:
This is a lightweight, thread-safe helper used by other parts of the driver (e.g., message dispatch routines, cleanup paths, or telemetry functions) to quickly poll or verify whether the user-mode client is alive and authenticated without needing to acquire a heavy lock or check multiple globals.

### 5.4 The message dispatcher and command surface

The hub is `MessageNotifyCallback` (`sub_140228B00`). On each received message it:

1. **Validates the port cookie.** It compares the `PortCookie` parameter (supplied by the Filter Manager) against the stored session cookie `qword_1408B3C98`. This ensures the message originates from the authenticated client connection.

2. **Checks the client connection state.** It atomically reads `dword_1408B3C90` to confirm that a client is currently connected. This is a state query, not a lock acquisition.

3. **Verifies driver readiness.** It calls `sub_1402280E0()` (likely a helper that reads a separate initialization flag) to ensure the driver is fully operational before processing commands.

4. **Validates input parameters.** It enforces a minimum input size of `4` bytes, checks for null buffers, and ensures output buffers are consistent.

5. **Routes the command.** It switches on the **first DWORD** (`*InputBuffer`) of the message body. The decompiled code reveals a large dispatch tree that handles at least **47 distinct opcodes** (ranging from `0x00` to `0x2E`, with gaps), including:

   - `0x00` → `sub_14022EAE0`
   - `0x01` → `sub_140232420`
   - `0x02` → `sub_140232880`
   - `0x03` → `sub_140231100`
   - `0x04` → `sub_1402332C0`
   - `0x05` → `sub_14022D780`
   - `0x06` → `sub_1402312A0`
   - `0x07` → `sub_14022CC80`
   - `0x08` → `sub_14022C580`
   - `0x09` → `sub_14022D700`
   - `0x0A` → `sub_14022D8E0`
   - `0x0B` → `sub_140231400`
   - `0x0C` → `sub_140232AC0` (with a flag)
   - `0x0D` → `sub_14022E0E0`
   - `0x0E` → `sub_14022EBC0`
   - ...and continues through `0x1A`, `0x27`, `0x2E`, etc.

   Unknown opcodes fall through to a default handler (`sub_14022ED40`) which rejects the message.

This dispatcher is the ATC control surface: every configuration write, query, and policy change from user mode lands here. Mapping each handler's semantics is outstanding work (§12).

### 5.5 The outbound path and `FltSendMessage`

Outbound notifications are centralized in `sub_14032AC80`, a wrapper over `FltSendMessage` that:

- **Applies a timeout.** It reads `dword_1408B3B78` (a DWORD timeout value) and converts it to a negative 100-nanosecond interval (`-10000000 * value`) to pass as a relative timeout to `FltSendMessage`.

- **Conditionally caps message size.** Only when the `a6` flag is non-zero does the wrapper enforce a maximum message size of `0xFFF0` bytes (just under 64 KB). If `a6` is zero, the length check is skipped entirely and the buffer is passed through unchanged. When the cap is exceeded (and `a6` is set), the function bypasses `FltSendMessage` and routes to a fallback handler (`sub_140424920`), likely for error logging or size-rejection handling.

- **Does NOT enforce connection state.** Unlike the message dispatcher, this send wrapper performs no custom checks for `dword_1408B3C90`, `::ClientPort`, or any other "client alive" flags. It relies purely on the Filter Manager's `FltSendMessage` API to validate the port handle and handle disconnection gracefully.

- **Handles timeouts explicitly.** If `FltSendMessage` returns `258` (`STATUS_TIMEOUT`), the wrapper translates it to a custom driver error code (`3892576326LL`, or `0xE8040006`).

Centralizing the send path is defensive engineering: one place to enforce timeout, size (conditionally), and timeout handling means consistent behavior across the driver. The near-64 KB cap—when enabled—is a size guard, likely a deliberate anti-fragmentation / anti-DoS limit for kernel pools.

---

## 6. The behavioral detection pipeline

This is the heart of ATC. The recovered flow:

```
minifilter callbacks
   -> event classification        (three dispatch arms)
   -> behavior switch             sub_14037C960
   -> suspicion / heuristics      sub_14037E8C0
   -> verdict validator           sub_1404683A0
   -> action queue                piNoAction / piKillProcess / piSendActions ...
   -> (if kill) worker            unk_1408B4720
```

### 6.1 Event classification

Events arrive from the registered callbacks and are normalized by three pre-operation dispatch
arms (`0x140651DC0`, `0x14064E830`, `0x14065000`) into internal event identifiers. The network
path feeds in here too: decoded HTTP flows from the WFP sensor are mapped to the same event
namespace, which is how file behavior and network behavior end up scoring the same process.

### 6.2 The behavior switch

`sub_14037C960` switches on the classified event identifier and selects the appropriate heuristic
evaluator. It is the *router* of the detector: it decides **which** checks run for a given event
class, not *whether* something is malicious. Routing is intentionally separate from judging so
that new event types can be added without reworking the scoring core.

### 6.3 The suspicion engine

`sub_14037E8C0` is the scoring core. It **accumulates suspicion** for the process under watch and
pulls evidence from multiple sources:

- its own heuristics database;
- module/"watchdog" results (suspicious loads, hook anomalies);
- interpreter hooks (Python/.NET, §8.3);
- network flow context from the WFP sensor (§8.4).

The important conceptual point: **detection here is a scoring problem, not a boolean problem.**
Individual weak signals (a stack pivot here, a direct syscall there, a suspicious module load over
there) are weighted and combined. No single signal necessarily trips a detection; the *combination*
does. That is the behavioral philosophy made concrete, and it is why ATC can catch threats whose
individual actions look innocuous.

### 6.4 Verdict and action model

`sub_1404683A0` consolidates the signals into a verdict, expressed with an enum family visible in
the binary:

- `piNoAction` — do nothing;
- `piKillProcess` — terminate the subject process;
- `piSendActions` — forward a richer action set;
- `IntegratorResponse` / `ShouldNotifyIntegrator` — defer to the user-mode Integrator.

This is the kernel/user-mode policy boundary: **the kernel proposes, the agent decides.** The
kernel computes verdicts and emits action tokens; the user-mode Integrator (the GravityZone/EDR
agent) is notified and owns final remediation policy. The strings `EDR Terminate` and
`EDR Freeze` tie this to the EDR product line's remediation actions.

---

## 7. Process termination

When the verdict is `piKillProcess`, termination runs in an **asynchronous worker**, not inline
in the callback:

```
verdict reached
   -> job enqueued into worker queue   unk_1408B4720
worker (sub_140497540)
   -> execute the job                  sub_140499A20
       -> open the target process
       -> ZwTerminateProcess(..., 0xC0000022)
```

Facts established:

- `ZwTerminateProcess` is imported and called from **exactly one** site in the driver. There is
  no second, hidden kill path.
- The exit status handed to the victim is `0xC0000022` (`STATUS_ACCESS_DENIED`) — the value the
  terminating process observes as its exit code.
- The worker queue (`unk_1408B4720`) decouples *deciding* from *doing*. This matters at a
  technical level: killing a process from inside a minifilter callback would violate IRQL
  expectations and stall the initiating I/O. By deferring to a worker at `PASSIVE_LEVEL`, the
  driver keeps the pipeline responsive while termination proceeds in the background.

The net effect: ATC does not merely *report* a malicious process. The driver is physically capable
of terminating it in kernel mode, at the appropriate IRQL, through a single audited code path.

---

## 8. Detection surface

This section is driven by the string table and the imported routine set. Where I say a string was
observed, it is a fact; where I interpret its purpose, I say so.

### 8.1 Process, thread, and image monitoring

The driver consumes process/thread/load-image notifications and tracks:

- process creation and termination, including parent/child relationships;
- image loads, with attention to suspicious modules;
- "forked" processes and mutation via memory writes (`NtWriteVirtualMemory`-style);
- **process hollowing** — confirmed by the string `ProcessHollowing`.

Process hollowing is a canonical EDR watch item: a legitimately-signed process is started, its
image is overwritten in memory, and the attacker's payload runs under a trusted identity. Catching
that requires correlating image-map events with memory-write events — which is exactly the kind of
cross-source correlation the pipeline in §6 is built for.

### 8.2 Anti-evasion heuristics

The binary names a large catalog of evasion techniques (all observed strings):

| String | Technique |
|--------|-----------|
| `HeavenGate` | "Heaven's Gate": crossing the 32/64-bit syscall boundary to dodge hooks |
| `DirectSyscall`, `Syscall` | calling syscalls directly to bypass user-mode API hooks |
| `Rop`, `StackPivot`, `StackShell`, `StackSpoofing` | stack/ROP-based obfuscation |
| `StolenToken` | stealing a privileged process's token |
| `ReflectiveDll` | reflective DLL injection (self-mapping, no loader participation) |
| `ParentSpoofing` | faking the parent process ID |
| `ModuleHook`, `ModuleStomp` | hooking or overwriting module code |
| `Unexpected Syscall`, `Sig Scan`, `EPR shell` | additional syscall/signature anomalies |

Why this matters conceptually: the presence of this catalog tells us ATC isn't only watching *what*
programs do — it watches for programs that appear to be **trying to avoid being watched**. That is
the distinguishing trait of defense-aware malware, and detecting it is one of the hardest and most
valuable things an EDR does.

### 8.3 Interpreter hooking (Python, .NET, AMSI)

The driver hooks interpreter and runtime entry points so it sees script *execution*, not just
script bytes:

- **Python:** `PyEval_EvalCode`, `PyRun_StringFlags`
- **.NET:** `mscoree.dll`, `coreclr.dll`, `LdrLoadDll`
- **AMSI:** AMSI context fields

The reasoning is elegant: fileless malware often ships an obfuscated script that only becomes
readable *at runtime*, when it is decrypted and about to be interpreted. If you hook the
interpreter itself — `PyEval_EvalCode`, the CLR entry points — you see the payload at the exact
moment of execution, already deobfuscated. This is how ATC catches scripts that would sail past
on-disk scanners.

### 8.4 WFP network sensor and in-kernel HTTP parsing

This is a major finding: `atc.sys` is **not just a file driver**. It registers **WFP (Windows
Filtering Platform) callouts** and inspects network traffic. Observed imports:

- `FwpsCopyStreamDataToBuffer0` — copy reassembled stream data;
- `FwpsFlowAssociateContext0` — associate a network flow with driver context;
- `FwpmFilterAdd0` — add a WFP filter;
- callout register/unregister functions (`fwpkclnt.sys`).

On top of that plumbing sits an **HTTP parser running inside the kernel**:

- `ConsumeHttpRequestLine`, `ConsumeHttpHeaders`, `ConsumeHttpBody`
- HTTP fields such as `Host:`, `User-Agent:`, `Content-Encoding:`, `Allow:`
- flow-direction context (`FlowDirectionInfo`) tracking connections per process

Observed network telemetry fields: `ConnectionsCount`, `ConnectedIPs`, `RemoteUrl`, `DNSQueries`,
`RemotePort`, `ListenInitialMovementRemoteIp`.

What this means, technically: HTTP-level inspection — URLs, headers, and content attributes — is
performed **in kernel space**, on reassembled flows, as part of the behavioral pipeline. That
allows the driver to correlate a process's network behavior with its local behavior without
round-tripping packets to user mode. The `DpiVersion` string in the version block (§3) is the
confirmation of intent: this is the DPI component of ATC.

### 8.5 Credential and logon telemetry

A focused field set relates to authentication (all observed):

- `TokenType`, `LUID`
- `NtPasswordPresent`, `LmPasswordPresent`, `PasswordExpired`
- `OriginalUserSid`, `ImpersonatedUserSid`
- `AreLmEqual`, `AreNtlmEqual`, `RaiseLogin`

**Careful reading.** These strings exist. They suggest the driver observes logon/NTLM-related
events — the kind of signal used to detect pass-the-hash, logon anomalies, and impersonation abuse.
Whether every field is actively populated in every build is a question for dynamic testing; what
is fact is that the field names are present in the binary's data structures.

### 8.6 Detection categories

The engine classifies verdicts into named categories (observed strings):

```
detection, beta detection, prometheus, game detection, ml detection, rsp detection, cbe detection
```

- `detection` / `beta detection` — stable and experimental heuristics;
- `ml detection` — machine-learning verdicts;
- `game detection` — gaming-mode / anti-cheat compatibility exceptions;
- `rsp detection`, `cbe detection` — likely remote-behavioral and cloud-behavioral sources
  (labeled as inference).

The coexistence of local heuristics, ML verdicts, and cloud-behavioral sources in one namespace is
the modern EDR model: multiple detectors, one unified verdict feed.

---

## 9. Tamper defense

The driver takes an active interest in the OS's internal callback arrays (observed strings):

- `PspCreateProcessNotifyRoutine`
- `PspCreateThreadNotifyRoutine`
- `PspLoadImageNotifyRoutine`
- `CallbackListHead`

These are the kernel's own lists of which drivers registered for process/thread/image
notifications. A normal driver never touches them. An EDR driver reads — and sometimes patches —
them, for two purposes:

1. **Situational awareness.** Knowing who else registered tells the driver which other EDRs,
   anti-cheats, or rootkits are present, and whether any of them are hooking the same structures
   to hide from each other.
2. **Self-protection.** Strings like `DualProtectedProcessTerminate` and `UmAntiTamper` indicate
   the driver defends its own processes from being terminated or modified.

This is the signature of a hardened, productized EDR driver rather than a research prototype.
Rootkits and "AV killers" abuse these same structures to hide processes and disable protections;
an EDR that watches the watchers is doing its job.

---

## 10. Telemetry and event serialization

Events are serialized and shipped to the user-mode client (observed strings):

- framing: `JsonEvent`, `event_time`, `machineEntropy`, `machine_arch`, `host_name`
- orchestration: `TriggerHeuristicForProcess`, `TriggerEngineRequest`
- feedback: `FeedbackFile*`, `PrometheusFeedbackFile`, `DsSendAsyncRequestToCore`

The picture: the driver builds structured (JSON-like) events, triggers heuristics per-process,
and ships results upward. `DsSendAsyncRequestToCore` and the Integrator tokens are strong evidence
that telemetry is relayed through the user-mode agent to Bitdefender's core/cloud. **There is no
dashboard socket inside this driver.** The cloud leg lives in user mode, behind the authenticated
local port described in §5.

Two strings tie the loop: `EDR Terminate` and `EDR Freeze`. They confirm ATC is integrated with
the EDR product line's remediation actions — the agent doesn't just get a report, it gets an
actionable verdict it can act on.

---

## 11. Synthesis — how the pieces fit

Put together, `atc.sys` is:

- a **minifilter** with a stable GUID and broad pre-operation coverage (§4);
- **two single-connection ports**, guarded by a cryptographic handshake, per-session cookies, and
  single-flight serialization (§5);
- a **staged behavioral pipeline**: classify → route → score → validate → act (§6);
- an **asynchronous kill worker** with exactly one `ZwTerminateProcess` call site (§7);
- a **network sensor** with in-kernel HTTP parsing (WFP) (§8.4), **interpreter hooks** for
  Python/.NET (§8.3), **credential/logon telemetry** (§8.5), and **tamper defense** over the OS
  callback arrays (§9);
- and, above all, a clean separation of powers: **the kernel proposes, the agent decides** (§6.4).

The design is coherent and deliberately layered: the kernel collects rich behavioral signal, the
control channel is authenticated and serialized, and remediation policy lives in user mode where
it can be updated without shipping a new driver.

---

## 12. Open questions and next steps

Static analysis has limits, stated plainly:

1. **The actual port name string.** Runtime-assembled into `byte_1408B42C0`;
   `sub_1401E617C` is a getter, not the builder. Recovery options:
   - trace the `FltCreateCommunicationPort` call sites in `sub_1405EECE0` / `sub_140227DE0` and
     dump the `UNICODE_STRING` argument;
   - on a live system, read the name with `!fltkd.ports` / `fltmc ports`.
2. **Which process connects.** We store the client PID/EPROCESS (`qword_1408B4338` / `Process`),
   but confirming which process that is (the one hosting `atcuf64.dll`) needs a live system.
3. **The full command table.** The ~27 dispatch slots (0x00–0x1A) are confirmed; individual
   handler semantics are not yet mapped.
4. **Scoring internals.** `sub_1404683A0` may consult scoring state we could not fully reach
   statically.
5. **WFP callout details.** The callout GUIDs and exact filter conditions would tell us precisely
   which flows are inspected.

---

## Appendix A — Key global symbols

| Symbol | Role |
|--------|------|
| `byte_1408B42C0` | Runtime-assembled port-name buffer |
| `byte_1408B4328` | "Client connected" flag |
| `qword_1408B3C98` | Per-connection session cookie |
| `dword_1408B3C90` | Single-flight message guard |
| `dword_1408B3B78` | Outbound message timeout |
| `qword_1408B4338` | Connecting client PID |
| `Process` | Connecting client EPROCESS |
| `unk_1408B4720` | Kill worker queue |
| `0x1407C2790` | Pre-op / pool table |
| `stru_1408B1D20` | Driver state container |

## Appendix B — Observed strings (raw evidence)

**Anti-evasion:** `HeavenGate`, `DirectSyscall`, `Syscall`, `Rop`, `StackPivot`, `StackShell`,
`StackSpoofing`, `StolenToken`, `ReflectiveDll`, `ProcessHollowing`, `ParentSpoofing`,
`ModuleHook`, `ModuleStomp`, `Unexpected Syscall`, `Sig Scan`, `EPR shell`

**Network:** `ConnectionsCount`, `ConnectedIPs`, `RemoteUrl`, `DNSQueries`, `RemotePort`,
`ListenInitialMovementRemoteIp`, `FlowDirectionInfo`

**HTTP parser:** `ConsumeHttpRequestLine`, `ConsumeHttpHeaders`, `ConsumeHttpBody`, `Host:`,
`User-Agent:`, `Content-Encoding:`, `Allow:`

**Credentials/logon:** `TokenType`, `LUID`, `NtPasswordPresent`, `LmPasswordPresent`,
`PasswordExpired`, `OriginalUserSid`, `ImpersonatedUserSid`, `AreLmEqual`, `AreNtlmEqual`,
`RaiseLogin`

**Scripting/.NET:** `PyEval_EvalCode`, `PyRun_StringFlags`, `mscoree.dll`, `coreclr.dll`,
`LdrLoadDll`, `AmsiContext`

**Decisions/actions:** `piNoAction`, `piKillProcess`, `piSendActions`, `IntegratorResponse`,
`ShouldNotifyIntegrator`, `EDR Terminate`, `EDR Freeze`

**Tamper defense:** `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`,
`PspLoadImageNotifyRoutine`, `CallbackListHead`, `DualProtectedProcessTerminate`, `UmAntiTamper`

**Detection categories:** `detection`, `beta detection`, `prometheus`, `game detection`,
`ml detection`, `rsp detection`, `cbe detection`

**Telemetry:** `JsonEvent`, `event_time`, `machineEntropy`, `machine_arch`, `host_name`,
`TriggerHeuristicForProcess`, `TriggerEngineRequest`, `FeedbackFile*`, `PrometheusFeedbackFile`,
`DsSendAsyncRequestToCore`

## Appendix C — Key imports

- **Filter Manager:** `FltRegisterFilter`, `FltCreateCommunicationPort`,
  `FltBuildDefaultSecurityDescriptor`, `FltSendMessage`
- **Process / NT:** `ZwTerminateProcess`, `ZwOpenProcess`, `ZwProtectVirtualMemory`,
  `ZwRead/WriteVirtualMemory`, `NtQueueApcThread`
- **Callbacks:** process/thread/load-image/registry/object notification registration
- **WFP:** `FwpsCopyStreamDataToBuffer0`, `FwpsFlowAssociateContext0`, `FwpmFilterAdd0`
- **Crypto:** `BCryptVerifySignature*` (CNG) — signature verification of modules/executables
- **AMSI / CLR / scripting:** AMSI context primitives, `mscoree.dll`, `coreclr.dll`
- **Security:** `SeAccessCheck`, security descriptor management

## Appendix D — Glossary

- **Minifilter** — a kernel driver that plugs into the Filter Manager's I/O pipeline.
- **Filter altitude** — the ordered position of a minifilter in the I/O stack.
- **GUID** — a unique identifier; here, the filter's permanent fingerprint.
- **IPC** — inter-process communication; message exchange between a driver and user-mode code.
- **WFP** — Windows Filtering Platform, the kernel framework for inspecting/altering network
  traffic.
- **Attestation** — proving possession of a secret before being trusted.
- **Cookie** — a session token; proves a message belongs to an authenticated session.
- **IRQL / PASSIVE_LEVEL / APC_LEVEL** — Windows interrupt priority levels; heavy work like
  killing a process must run at the lowest one.
- **Heuristics** — rules based on behavior rather than exact known-malware fingerprints.
- **Reflective DLL injection** — loading a DLL entirely in memory, without the OS loader.

---

## Disclaimer

This document is a defensive, static reverse-engineering exercise on a commercially licensed EDR
driver. It describes observable interfaces and recovered architecture for the purpose of
understanding how kernel-mode endpoint protection works. It describes no security vulnerability,
and no vulnerability claim is made. All addresses are flat virtual addresses from the specific
build analyzed (v1.84.443.0) and will differ on other builds. Items labeled "likely" or
"inferred" are interpretations of observed strings/imports and should be validated dynamically
before being relied upon. Strings in a driver are evidence of intent, not proof of behavior.
this is just static analysis so some sections may be wrong so please feel free to tell me


# Inside Bitdefender's Trufos Real-Time Protection Driver (`trufos.sys`)

### A technical deep-dive into a production kernel sensor: bootstrap, authenticated IPC, the 27-command surface, image validation, registry blocking, raw-NTFS directory accounting, and token-handle operations

**Target:** `trufos.sys`
**Symbol source:** `C:\trufos\bin\x64\ReleaseKernel\trufos.pdb`
**Build metadata:** compiled `Jun 25 2026`, identifier `c86a5d46`
**Method:** Static reverse engineering (IDA Pro, x64, flat virtual addresses)
**Intended audience:** Security researchers, EDR/AV developers, kernel engineers, malware analysts, and threat-hunting teams

---

## Reading guide and evidence model

This document is written for readers who already know what a minifilter is and what `IRQL`
means. It still explains *why* the design choices matter, because that is where the real insight
lives.

Before anything else, one methodological point, stated once and honored throughout:

> **A string or an import in a driver is evidence of intent, not proof of behavior.**

To keep the two apart, this document uses a strict vocabulary:

- **Observed** — present in the binary: a string, an import, a control-flow edge, a constant.
- **Recovered** — a control-flow structure (call tree, switch, loop) that we traced in IDA.
- **Inferred / likely** — an interpretation of observations based on how Windows works and how
  EDR products are built. These are labeled every time they appear.

Every address is a flat virtual address valid for this specific build. Other builds will have
different addresses.

---

## Table of Contents

1. What `trufos.sys` is and what this document covers
2. Build identity and what it leaks
3. Bootstrap and initialization
4. The IPC architecture
   4.1. The communication port
   4.2. Connection access control and the version handshake
   4.3. The message dispatcher and the 27-command surface
5. Subsystem: asynchronous image validation (`TrfBlockImage`, command 4)
6. Subsystem: registry tamper blocking (`regblock`, command 12)
7. Subsystem: raw-NTFS directory counting (`rawdircnt`, command 16)
8. Subsystem: token-handle operations (command 22)
9. Self-protection and reliability measures
10. Synthesis — how the pieces fit
11. Open questions and next steps
12. Appendices
    A. Key global symbols
    B. Observed strings (raw evidence)
    C. Observed source paths
    D. Key imports
    E. Command dispatch table
    F. Glossary

---

## 1. What `trufos.sys` is and what this document covers

`trufos.sys` is a **kernel-resident real-time protection driver** in the Bitdefender ecosystem.
Where `atc.sys` (the Advanced Threat Control engine) scores *behavior*, `trufos.sys` provides the
**on-access, on-demand protection primitives** that sit close to the operating system: deciding what
images are allowed, blocking registry tampering, counting directory contents at the file-system
level, and performing process/token operations. In modern Bitdefender deployments the two drivers
complement one another.

What this document reconstructs, from static analysis:

- How the driver registers and reads its configuration (`drvinit.c`, `context.c`, `prfmiddle.c`).
- How it publishes exactly one communication port and how access to it is gated.
- The full message-dispatcher command surface (27 handlers) and the four we traced in depth.
- The self-protection and reliability measures baked into the design.

---

## 2. Build identity and what it leaks

The binary identifies itself clearly through its PDB path and build metadata:

```
PDB path   :  C:\trufos\bin\x64\ReleaseKernel\trufos.pdb
Build date :  Jun 25 2026
Hash       :  c86a5d46
```

Three facts come out of these lines:

1. **Release configuration.** `x64\ReleaseKernel` tells us this is a 64-bit kernel driver built in a
   **Release** configuration (optimizations enabled, but PDB symbols kept for internal trace paths).
2. **Source tree layout.** The PDB root is `C:\trufos\`, with a top-level `trufos` directory. The
   source paths embedded in the binary (Appendix C) map the product's internal division of labor.
3. **Private file-name evidence.** The referenced sources name the driver's own components: registry
   blocking (`regblock.c`), raw directory counting (`rawdircnt.c`), user-mode library communication
   (`umlibcomm.c` / `umlibcommands.c`), driver init (`drvinit.c`), context management (cage), and a
   performance-mid layer (`prfmiddle.c`). The IPC plumbing lives under a dedicated `petrulib` folder.
   These are internal names and they leak design intent.

---

## 3. Bootstrap and initialization

Recovered initialization facts:

- **Safe-mode block.** The driver refuses to load in Windows Safe Mode, returning
  `STATUS_DRIVER_BLOCKED`. Safe mode is where self-healing and repair tooling runs; a protection
  driver that cannot trust the environment refuses rather than risk being partially effective.
- **Driver context.** A single per-driver context of **0x7D0 bytes**, pool-tagged `'TRF:'`
  (`0x53465254` as the dword tag), constructed from `stru_1400925E0`.
- **Locking.** Two dedicated locks: an `UnloadLock` at context `+0x150` and a
  `RegistryBlockLock` at context `+0x688` used by the `regblock` subsystem.
- **Configuration from the registry.** The driver verifies a configuration path (the `a2`
  argument to its init path), locates components from the registry, and keeps post-reboot tracking
  via `AfterRebootComandsList` and `AfterRebootResultsComandList` — a mechanism for deferring
  actions until a later boot.
- **Enablement state machine.** A "BDM" (boot/decision manager) state machine controls the effective
  operating state through `BdmInitData`, `BdmEvaluateState`, and `BdmSetAndSaveState`. This is the
  switch that lets the product enable or disable the driver's protections around a specific state.
- **Dynamic syscall resolution.** Rather than relying solely on imported NT routines, the driver
  resolves calls dynamically — an anti-patching / self-reliance measure (§9).
- **Device-object state checks.** Many paths begin with a guard on the global `DeviceObject`,
  checking its state before dereferencing and frequently preceded by `lfence` — the release-build
  reliability scaffolding.

---

## 4. The IPC architecture

### 4.1 The communication port

`trufos.sys` publishes **one** communication channel. Despite the user-mode library references
(`umlibcomm.c`, `umlibcommands.c`), the low-level transport is a single Filter Manager port:

| Fact | Value |
|------|-------|
| Port object name | `TRFCOMMPORT` |
| Server filename | `trufosportserver` |
| Client-list symbol | `TrufosConnectedClients` |
| Peak connections | 1 (`MaxConnections = 1`) |
| Connect callback | `sub_1400405E0` (version handshake) |
| Message / broadcast | `sub_14003F890` |
| Dispatcher | `sub_1400408B0` (27-command switch) |

Initialization is orchestrated by `sub_140040194`, which:

1. Builds the object name via `RtlInitUnicodeString` for `TRFCOMMPORT`.
2. Fills a `petrulib` port-request structure (name, security, callbacks, `MaxConnections = 1`).
3. Calls the port factory `sub_140066834` → `sub_140066BEC` → the actual
   `FltCreateCommunicationPort` wrapper, whose source code lives in
   **`C:\trufos\petrulib\ptport.c`** and **`ptportflt.c`**.

The `petrulib` layer allocates the port/connection object, initializes a connected-client list
(`LstAllocAndInit` / `LstInsertHead`), and frees it on failure — all logged against
`ptport.c` / `ptportflt.c`.

![ports](/assets/port1.png)
![ports](/assets/port2.png)

### 4.2 Connection access control and the version handshake

The port is not an open door:

- **Security descriptor.** The port is created with
  `FltBuildDefaultSecurityDescriptor(0x1F0001)`, the Filter Manager default descriptor, which
  grants access only to **SYSTEM and the local Administrators group**.
- **Maximum connections.** `MaxConnections` is limited (each port context allocates a small
  multi-connection table, capped at `0x10`).
- **Version handshake (`sub_1400405E0`).** A connecting client must supply a **16-byte** context
  whose first three DWORDs are `{2, 7, 2}` — a **version triple** (major 2, minor 7, build 2).
  Clients that fail the handshake are rejected.
- **Client identity capture.** On a valid connect the driver captures `PsGetCurrentProcessId()` and
  a seed value read from `KUSER_SHARED_DATA+0x14` (a system-time field used as an anti-replay /
  uniqueness seed) and passes both to `sub_14003F354`, which allocates and links a per-connection
  client object into `TrufosConnectedClients`.

So the driver authenticates not by the object's access check alone, but by *who* proves the version
— a defense-in-depth gate on an SYSTEM/admin-only port.

![ports](/assets/sec.png)
![ports](/assets/seci.png)
![ports](/assets/version.png)

### 4.3 The message dispatcher and the 27-command surface

`sub_1400408B0` is the message-notify root. It is a **value switch on the first DWORD of the message**
and routes to **27 command handlers**. The registry of that dispatch is in Appendix E.

Each handler shares a common signature:

```
status = handler(InputBuffer, InputLength, OutputBuffer, OutputLength, ReturnLength)
```

- Validates `InputBuffer/Length` and `OutputBuffer/Length` up front.
- A small fixed set of outputs (e.g. `*ReturnLength = 8` or `12`) is written back on success.
- Failures are recorded through an internal trace channel, then a fixed status is returned.

Three handlers account for most of the interesting behavior and are studied in depth below:
`4` (image validation), `12` (registry blocking), and `16` (raw directory counting). Handler `22`
runs a token-handle duplication worker. The remaining handlers form the broader protection /
configuration surface.

---

![ports](/assets/dispatching.png)


## 5. Subsystem driver: image validation (`TrfBlockImage`, command 4)

**Handler:** `sub_14000899C` — **`TrfBlockImage`**

This is the image-open validation path: it lets user mode request a verdict on a given image before
the caller trusts it.

**Input contract:** `a1` (input) ≥ `0x20` bytes, `a4` (output) ≥ 8; the input carries an **open
handle to an image file** at `a1+8` and further parameters later in the buffer.

1. **Resolve the real file object.**
   `ObReferenceObjectByHandle(*(HANDLE*)(a1+8), 0, IoFileObjectType)` obtains the file object, then
   **`TrfGetRealFileObject`** (`sub_140032864`) retrieves the *real* `FILE_OBJECT` beneath any
   filter/file object, using the Win8+ path when the OS version permits (the
   `major==6 && minor>=2` branch).
2. **Build identity.** `sub_140032830` derives a path/context, `sub_140009084` builds a data list,
   and `sub_140007AFC` looks up the object; `sub_14005C6A0` joins it into a per-path structure.
3. **Serialize with a lock.** `sub_140058D04` (a `LockAcquire`) guards the global state.
4. **Pick a worker slot.** The code scans a fixed **100-entry** array of 40-byte slots
   (`DeviceObjectExtension`), zero-initializes a free slot, and copies its input identity into it.
5. **Spawn a worker thread.** `PsCreateSystemThread(..., StartRoutine: sub_140009120)` launches an
   asynchronous decision thread that owns the slot; a global counter is incremented (interlocked).

**Worker `sub_140009120` (the decision thread):**

1. `KeWaitForSingleObject` on a global synchronization object with a bounded **timeout** carried in
   the slot.
2. **On wait (timeout):** `LstWalk` (`sub_14005C928`) over the pending-item list, calling the
   per-item callback **`sub_1400088D0`**.
3. **Per-item callback `sub_1400088D0`:** matches a key at `entry+40` against the worker input;
   on match it destroys/frees the list entry (`sub_140007D60`), sets the done flag on the output
   (`*a4 |= 3`), and returns the LstWalk "consume and stop" sentinel (`0x68000037`).
4. Finish: `LstDereferenceList`, `PsTerminateSystemThread`.

**Meaning.** Image validation in this driver is **asynchronous and timeout-bounded**. User mode
presents an image; the driver resolves it, attaches an identity, and defers the allow/block to a
worker that waits a bounded window and then walks a pending list. The intent is to validate while
keeping the caller's I/O responsive — a common pattern for on-access image trust checks.

![ports](/assets/image.png)
![ports](/assets/imaging.png)
![ports](/assets/terminate.png)

---



## 6. Subsystem driver: registry blocking (`regblock`, command 12)

**Handler:** `sub_140032CF4`

This is the **registry tamper blocker**: user-mode can register a rule that denies write operations
to a chosen registry path.

**Input contract:** `InputLength >= 0x20`. Two WORD lengths at offsets 26 and 28 declare two data
regions, with the invariant `SizeOfData1` + `SizeOfData2` + 32 == InputLength. Data1 at `+30`,
Data2 at `+30+SizeOfData1`. A `mode` DWORD at `+4` (values 1..6) selects the operation variant;
data is copied as `UNICODE_STRING`-style buffers.

**Registering:**

1. Copies Data1 → `UNICODE_STRING` buffer, Data2 → another (if `Size2 != 0`), both allocated with
   the pool tag `0x4843573A`.
2. Allocates a **0x50-byte rule context** (tag `0x4B52543A`), zeroed, and records:
   - the mode (`ctx+72`);
   - `a1+24` / `a1+25` flag bytes into `ctx+64` and `ctx+65`;
   - a rule ID fetched from the global interlocked counter `dword_140092150`.
3. Stores the two data strings via `UstrAllocAndInitBufferFromUstr` (`sub_14005A790`).
4. **Optional scoping:** if `ctx+65 == 1`, resolves a target via
   `PsLookupProcessByProcessId(a1+16)` and stores the EPROCESS; if `ctx+64 == 1`, resolves a target
   thread via `PsLookupThreadByThreadId(a1+8)` and stores ETHREAD.
5. **Callback registration (one-time).** On first use a latch is set and `TrfRegBlockRegisterCallbacks`
   (`sub_140033A30`) is invoked to install the enforcement hook (below).
6. The rule is inserted into the global rule list (via `LstInsertHead`),
   and the rule ID is written back to the caller.

### Enforcement (`sub_140033A30`)

```
RtlInitUnicodeString(&Altitude, L"320770");
CmRegisterCallbackEx(Function, Alt & 320770, Driver, Context=NULL, Cookie=&global, Reserved=NULL);
```

This registers a **Configuration Manager (registry) callback** at **altitude 320770**. That callback
is a single global function that the Filter Manager invokes before/after targeted registry
operations; it consults the user-registered rule list and **vetoes** writes that match an active rule
(optionally scoped to a specific process or thread).

The result is a filtered registry protection surface: add a rule on a path, and all configuration
callbacks matching it are denied — with optional per-process / per-thread scoping.

---

## 7. Subsystem driver: raw-NTFS directory scanning (`rawdircnt`, command 16)

**Handler:** `sub_140029FA8`

This subsystem is the **raw directory counter** — it enumerates/correlates directory contents at the
NTFS metadata level, independent of ordinary file-system APIs.

**Input contract:** `InputLength >= 0x10`. DWORD lengths at offsets 4 and 6, both **≥ 0x64
(100)**, with the invariant `Size1 + Size2 + 16 == InputLength`. Data1 at `+16` (next data at
`+16+2*(Size1/2)`).

**Flow:**

1. Copy Data1 and Data2 into two pooled buffers (each `len+2`, NULL-terminated) with the `0x4843573A`
   tag, and normalize them as UNICODE strings.
2. **`TrfSplitGuidPath`** (`sub_140014488`) — split a **GUID/device path** (e.g. `\??\Volume{GUID}\`)
   for each buffer into structured components.
3. Resolve the volume for each side: **`TrfGetRawNtfsInstanceForVolume`** (`sub_1400132E0`) —
   obtain the **raw NTFS minifilter instance** for that volume.
4. Check the two split paths correlate via `sub_14005AD80` (expects a fixed sentinel status).
5. **`RnTransferAttribute`** (`sub_140047E48`) — transfer/read an **attribute** between the two
   instances (a count / state quantity).
6. Report the result back in the output buffer.

**Why this matters:** by reading entries via the raw NTFS instance rather than standard
directories, the driver can observe directory-state churn (mass create/delete / enumeration) as
raw file-system signal — a view that is hard for user-mode subprocesses to hide and that feeds the
behavioral/ransomware-detection story. This is a classic kernel-side on-disk counting technique.

![ports](/assets/reg.png)

---

## 8. Subsystem: token-handle operations (command 22)

**Handler:** `sub_140017DC8` → coordinator `sub_140017B00` → worker `sub_1400176E0`

This command manages a **background job that duplicates an impersonation token into a target
process** — a handle-handoff capability.

**Coordinator (`sub_140017B00`):** serialized by a `Mutex`, it maintains a singleton job flag
(`byte_1400920E8`), a saved input (`qword_1400920F0`), and a saved output (`qword_1400920F8`,
`dword_140092100`, `dword_140092104`). In `start` mode (arg==1) it:
- if the job is already running, returns the saved output and `STATUS_IMAGE_ALREADY_LOADED`;
- otherwise initializes an event, spawns the worker `sub_1400176E0`, waits for its completion event,
  and records the thread reference.

In `stop` mode it signals the worker's stop event, waits, and releases the reference. This is a
**run-once / stop-on-command lifecycle**.

**Worker (`sub_1400176E0`):**
1. Open the **current process** (`ZwOpenProcess` on `PsGetCurrentProcessId`).
2. Open the **target process** (the job's target PID).
3. `ZwOpenProcessTokenEx` then **`ZwDuplicateToken(ExistingTokenHandle, ..., TokenImpersonation)`** —
   produce a duplicate impersonation token of the current process.
4. `ZwDuplicateObject` — transfer that **token handle into the target process** and record the
   resulting target handle, plus current PID/TID and a success flag into the job slot.
5. Close its local handles; the worker parks on the stop event until the coordinator signals done.

**What it does:** the driver duplicates a token-handle from its own process into user-selected target,
i.e. a handle-handoff / impersonation capability used by the product's background or
self-protection paths.

![ports](/assets/process.png)
![ports](/assets/processing.png)
---

## 9. Self-protection and reliability measures

`trufos.sys` is hardened by design. Observed measures:

- **Safe-mode refusal.** `STATUS_DRIVER_BLOCKED` when Safe Mode is detected; prevention of
  untrusted boot scenarios.
- **Access-gated IPC.** The port allows **SYSTEM/Administrators** only (default Filter Manager
  descriptor) and requires the `{2,7,2}` handshake — limiting who can reach the command surface.
- **Dynamic resolution.** Calls are resolved at runtime instead of static imports where possible,
  reducing the attack surface and resilience to static import patching.
- **Tamper-interested registry surfacing.** `CmRegisterCallback` at altitude `320770` installs an
  enforcement hook that vetoes matching registry writes consistently.
- **State machines and boundary replies.** The BDM enablement state machine plus per-feature
  latches (e.g. the one-time callback install) keep operations from running before they are
  explicitly enabled.
- **Abstraction to async workers.** Heavy operations (image validation, token handling) run on
  separate system threads with explicit events/mutexes and bounded timeouts, avoiding privileged
  stalls and aligning to IRQL constraints.
- **Configure-based placement.** Driver registers lock pairs (`UnlockLock`,
  `RegistryBlockLock`), pool-tag discipline, and `lfence`-preceded release guards.
- **Anti-replay/anti-spoof context.** The connect path binds a running timestamp-seeded value
  (`KUSER_SHARED_DATA+0x14`) to the client object, complicating spoofing/replay of a connection.
- **Rigorous validation.** Every handler enforces `InputLength`/`OutputLength` budgets and returns
  explicit NTSTATUS error codes (e.g. `0xC0000001`, `0xC00000EF`, `0xC00000F0`, `0xC00000F1`) on
  malformed or oversized requests rather than proceeding.

---

## 10. Synthesis

Put together, `trufos.sys` is a **reactive real-time protection driver** with:

- a **single SYSTEM/admin-gated Filter port** (`\TRFCOMMPORT`, version-gated),
- a **27-command dispatcher** covering image validation, registry tamper-blocking, raw-NTFS
  scanning, token/handle operations, and configuration,
- **worker-thread architecture** for the heavy paths,
- **CM-callback registry protection** (altitude 320770),
- a **BDM state machine** plus registry-driven configuration and post-reboot lists,
- and **defense-in-depth** (safe-mode block, dynamic resolution, descriptors, handshake,
  per-feature latches).

It complements `atc.sys` rather than duplicating it: `trufos` provides the lower-level protection
primitives and kernel-side coordination; `atc` provides the behavioral scoring layer above.

---

## 11. Open questions and next steps

Static analysis has limits, stated plainly:

1. **Exact registry paths.** The driver reads its policy from the registry (`drvinit.c`) but the
   specific value names/keys were not all instrumented; a live listing would name them.
2. **The `{2,7,2}` handshaker client.** Who is the expected peer that connects with that version
   (a Bitdefender service hosting `umlibcomm`)? Confirm dynamically.
3. **The remaining 20 handlers.** Commands 4, 12, 16, 22 are traced; the rest are mapped by address
   (Appendix E) but their detailed args/semantics are not yet documented.
4. **What the `Rn*` attribute transfer stores.** The exact attribute being relocated between
   raw-NTFS instances remains unresolved statically.
5. **Altitude interaction.** The `320770` CM altitude versus other registered filters/callbacks on
   a live system.

---

## Appendix A — Key global symbols

| Symbol | Role |
|--------|------|
| `stru_1400925E0` | Primary driver state/context container |
| `DeviceObject` | The driver's device object (global, switched by init) |
| `byte_1400920E8` | Token-worker job "running" flag |
| `qword_1400920F8` / `dword_140092100` / `dword_140092104` | Token-job output values |
| `dword_140092150` | Atomic registry rule-ID counter |
| `qword_140092108` | Token worker thread object reference |
| `TrufosConnectedClients` (list) | Connected client-object list |
| `dword_1400920F0` | Saved token-job input |
| `PFLT_PORT @ +0xB0` | Stored Filter port handle |
| `TRFCOMMPORT` | Port object name |

## Appendix B — Observed strings (raw evidence)

**Port/IPC:** `TRFCOMMPORT`, `trufosportserver`, `TrufosConnectedClients`

**Library/registry shell:** `UmLibCommAllocAndInitClientObject`, `UmLibCommDereferenceClient`,
`CmRegisterCallback`, altitude string `320770`, `CmRegisterCallbackEx`

**List/alloc scaffolding:** `LstAllocAndInit`, `LstInsertHead`, `LstDereferenceList`,
`UstrAllocAndInitBufferFromUstr`

**Runtime helpers (observed in trace helpers):** `LockAcquire`, `LockRelease`,
`KeWaitForSingleObject`, `KeReleaseMutex`, `PsCreateSystemThread`, `PsTerminateSystemThread`,
`ZwOpenProcess`, `ZwOpenProcessTokenEx`, `ZwDuplicateToken`, `ZwDuplicateObject`,
`ObReferenceObjectByHandle`

**Feature names:** `TrfBlockImage`, `TrfGetRealFileObject`, `TrfSplitGuidPath`,
`TrfGetRawNtfsInstanceForVolume`, `RnTransferAttribute`, `TrfRegBlockRegisterCallbacks`

**State/lifecycle:** `BdmInitData`, `BdmEvaluateState`, `BdmSetAndSaveState`,
`AfterRebootResultsComandList`, `AfterRebootComandsList`

**Pool/content tags:** `'TRF:'` (0x7D0 context), `0x4843573A` (string buffers),
`0x4B52543A` (registry rule context), `0x5254533A` (raw-dir instance),
`0x46545250` (petrulib filter object), `'PRF:'` (prfmiddle)

## Appendix C — Observed source paths (raw evidence)

- `C:\trufos\trufos\regblock.c`
- `C:\trufos\trufos\rawdircnt.c`
- `C:\trufos\trufos\umlibcomm.c`
- `C:\trufos\trufos\umlibcommands.c`
- `C:\trufos\trufos\drvinit.c`
- `C:\trufos\trufos\context.c`
- `C:\trufos\trufos\prfmiddle.c`
- `C:\trufos\petrulib\ptport.c`
- `C:\trufos\petrulib\ptportflt.c`

## Appendix D — Key imports / semantics

- **Filter Manager:** `FltCreateCommunicationPort`,
  `FltBuildDefaultSecurityDescriptor`, `FltFreeSecurityDescriptor`, `FltCloseCommunicationPort`
- **Configuration Manager:** `CmRegisterCallbackEx`
- **NT / process:** `ZwOpenProcess`, `ZwOpenProcessTokenEx`, `ZwDuplicateToken`, `ZwDuplicateObject`,
  `ZwClose`, `ObReferenceObjectByHandle`, `ObfDereferenceObject`
- **Kernel:** `PsCreateSystemThread`, `PsTerminateSystemThread`, `PsGetCurrentProcessId`,
  `PsGetCurrentThreadId`, `PsLookupProcessByProcessId`, `PsLookupThreadByThreadId`,
  `KeWaitForSingleObject`, `KeInitializeEvent`, `KeSetEvent`, `RtlInitUnicodeString`,
  `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `memset`

## Appendix E — Command dispatch table (27 entries)

| Index | Handler |
|-------|---------|
| 0 | `sub_1400260E8` (→ `sub_1400278A8`) |
| 1 | `sub_140025C8C` (→ `sub_140026638`) |
| 2 | `sub_140041C4C` |
| 3 | `sub_140041A5C` |
| 4 | `sub_14000899C` — `TrfBlockImage` (image validation) |
| 5 | `sub_140015054` (→ `sub_140015600`) |
| 6 | `sub_140015178` |
| 7 | `sub_1400127EC` |
| 9 | `sub_140042304` |
| 11 | `sub_14002B40C` |
| 12 | `sub_140032CF4` — `regblock` (registry blocking) |
| 13 | `sub_140033490` |
| 14 | `sub_14001B524` |
| 15 | `sub_14001B280` |
| 16 | `sub_140029FA8` — `rawdircnt` (raw-NTFS dir scan) |
| 18 | `sub_140017F0C` |
| 19 | `sub_14002D3BC` / `02D0A0` / `02D730` |
| 20 | `sub_14002D730` |
| 21 | `sub_14002DB54` |
| 22 | `sub_140017DC8` → `17B00` → `176E0` (token-handle op) |
| 23 | `sub_14002A924` |
| 24 | `sub_140029CC4` |
| 25 | `sub_14002AC50` |
| 26 | `sub_14002A5F8` |
| 27 | `sub_14002B8C8` |
| 28 | `sub_14002B0E0` |
| 29 | `sub_14000B718` |
| 30 | `sub_140018C88` |

## Appendix F — Glossary

- **Minifilter** — kernel driver that plugs into the Filter Manager's I/O pipeline.
- **Altitude** — the ordered position of a driver/callback in a stack.
- **CM callback** — Configuration Manager (registry) pre/post notification callback.
- **Raw NTFS instance** — a direct file-system instance handle to read on-disk state directly.
- **IPC port** — Filter Manager communication channel between a driver and user-mode processes.
- **PPL** — Protected Process Light; OS process-protection scheme.
- **KUSER_SHARED_DATA** — the kernel/user shared page holding low-level system state.

---
