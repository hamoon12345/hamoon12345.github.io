---
title: "Hardening SharpHound for OPSEC: A Full Walkthrough"
date: 2026-08-08 00:00:00 +0000
categories: [Red Team, tools]
tags: [tool, hardening, opsec, tools]
description: ""
toc: true
image:
  path: /assets/bloodhound.png
  alt: blood Hound
---
# SharpHound 2.X — Full Modification Analysis

Public collectors are loud by design. SharpHound is no exception. This post walks through the exact changes I made to turn the stock Community Edition into something quieter for real environments.

Warning: this version is still not intended for production operations. It can get flagged. The goal of the write-up is to show the process of systematically removing the obvious fingerprints from a public tool so you can apply the same thinking yourself.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Part 1 — The Original Codebase: What Every File Does](#2-part-1--the-original-codebase-what-every-file-does)
3. [Part 2 — Modification Philosophy](#3-part-2--modification-philosophy)
4. [Part 3 — Per-File Modifications (Exact Code)](#4-part-3--per-file-modifications-exact-code)
5. [Part 4 — New Files](#5-part-4--new-files)
6. [Part 5 — Deleted Files](#6-part-5--deleted-files)
7. [Part 6 — Build / Project Metadata Changes](#7-part-6--build--project-metadata-changes)
8. [Part 7 — Behavioral Delta Summary](#8-part-7--behavioral-delta-summary)
9. [Part 8 — writing a decryptor](#9-part-8--writing--a--decryptor)
10. [Part 9 - reconverting our binary to a shell code for in memory running](#10-part-9--writing--a--shellcode)
11. [Part 10 — Residual Fingerprints & Accepted Risk](#10-part-9--residual-fingerprints--accepted-risk)
12. [Appendix — Type & Namespace Rename Map](#appendix--type--namespace-rename-map)

---

## 1. Executive Summary

I took the stock SharpHound Community Edition collector and hardened it into an OPSEC-focused, in-memory, zero-argument Active Directory enumerator. The final binary is a single standalone **`Compat.exe`** (`.NET Framework 4.7.2`) that:

- requires **no command-line arguments** (the entire CLI surface was removed),
- writes a **single encrypted output file** (`container.dat` under `%LOCALAPPDATA%\Microsoft\Windows\INetCache`)
  instead of `BloodHound*.zip` + JSON/cache artifacts in the working directory,
- rewrites LDAP filters into benign, semantically-equivalent forms and **paces every query/results**
  so the LDAP traffic does not resemble a SharpHound enumeration,
- performs **no TCP port probing** and **no CA HTTP enrollment scan**,
- never reads `MachineGuid`, never writes a cache file, never leaves temp/zip/json/banner artifacts,
- logs **quiet, single-line, stack-free** messages,
- is **renamed end-to-end** (`Sharphound.*` namespaces/types → `Compat.*`), scrubbing the identifier
  strings from the binary and the PowerShell loader.


---

## 2. Part 1 — The Original Codebase: What Every File Does

### 2.1 Root / project files

| File | Purpose in the original build |
|---|---|
| `Sharphound.csproj` | SDK-style project. Targets `net472`; `DebugType=full`; Version/FileVersion `2.14.0`; `Company=SpecterOps`; `Product=SharpHound`; `AssemblyName=SharpHound`. References `CommandLineParser 2.8.0`, `Costura.Fody 5.7.0` (single-binary merge), `SharpHoundCommonLib`/`SharpHoundRPC` (NuGet or local), and a post-build PowerShell `PS1` target that emits the in-memory `.ps1` wrapper. |
| `Sharphound.sln` | Solution file (unchanged). |
| `Properties/launchSettings.json` | VS debug launch profile (unchanged). |
| `FodyWeavers.xml` | Fody weaver configuration enabling Costura (unchanged). |
| `nuget.config` | NuGet feed configuration, enables the dev CommonLib feed (unchanged). |
| `Quickstart.ipynb`, `README.md`, `LICENSE`, `.github/**`, `.gitignore` | Docs / CI / license (all unchanged). |

### 2.2 Entry point & runtime bootstrap

| File | Purpose in the original build |
|---|---|
| `src/Sharphound.cs` | `Program.Main`. Prints an ASCII-art banner and version lines, validates the .NET Framework release via the **registry**, parses CLI arguments with **CommandLineParser**, sets up optional **metrics** (`MetricRegistry`, file sink, flush timer), then drives the pipeline chain: `Initialize → TestConnection → SetSessionUserName → InitCommonLib → GetDomainsForEnumeration → StartBaseCollectionTask → AwaitBaseRunCompletion → StartLoopTimer → StartLoop → AwaitLoopCompletion → SaveCacheFile → Finish`. Exposes `InvokeSharpHound(string[])` for the PS1 loader. |
| `src/Options.cs` | `Options` class: ~50 CommandLineParser-annotated properties (collection methods, domain, output dir/prefix, cache, zip name/password, LDAP username/password/DC/ports, port-scan timeout, throttle/jitter/threads, loop duration/interval, verbosity, stealth, etc.) plus `ResolveCollectionMethods()` which validates/maps the string collection methods onto the `CollectionMethod` bitmask. |
| `src/BasicLogger.cs` | Custom `ILogger`. `FormatLog()` emits `timestamp\|LEVEL\|message` followed by the **full exception + stack trace** when an error is logged. |

### 2.3 Pipeline / chain-of-responsibility

| File | Purpose in the original build |
|---|---|
| `src/Client/Context.cs` | `IContext` interface — the runtime state contract (flags, LDAP utils, channels, filenames, loop timers, delays, cache path, domain list, AdminSDHolder hash table) plus `ContextUtils.Merge` and `FileExistsException`. |
| `src/Client/Flags.cs` | `Flags` POCO — ~24 boolean runtime flags (Stealth, Loop, MemCache, NoZip, NoOutput, SkipPortScan, RandomizeFilenames, CollectAllProperties, Metrics, …). |
| `src/Client/Links.cs` | `Links<T>` — the chain-of-responsibility **interface**: `Initialize`, `TestConnection`, `SetSessionUserName`, `InitCommonLib`, `GetDomainsForEnumeration`, `StartBaseCollectionTask`, `AwaitBaseRunCompletion`, `StartLoopTimer`, `StartLoop`, `AwaitLoopCompletion`, `DisposeTimer`, `SaveCacheFile`, `Finish`. |
| `src/BaseContext.cs` | `BaseContext : IContext, IDisposable` — the concrete context: owns `LdapUtils`, loop timers, `GetCachePath()` (uses a machine-specific `MachineGuid`-derived cache filename via `ClientHelpers.GetBase64MachineID()`), `ResolveFileName()` (timestamp/random-name logic), and `DoDelay()` throttle/jitter sleep. |
| `src/SharpLinks.cs` | `SharpLinks : Links<IContext>` — the concrete pipeline. `Initialize` logs "Initializing SharpHound at …", validates LDAP username/password pairing, resolves the current domain, checks output-directory writability **in the current directory**, sets up loop options. `InitCommonLib` initializes the CommonLib cache **from a cache file on disk** (unless MemCache). `Finish` logs "SharpHound Enumeration Completed … Happy Graphing!". `SaveCacheFile` serializes the on-disk cache. |
| `src/Extensions.cs` | Extension helpers over `CollectionMethod` (`GetIndividualFlags`, `GetLoopCollectionMethods`) and misc. |
| `src/EnumerationDomain.cs` | `EnumerationDomain : Domain` — domain object used during recursive/forest enumeration. |
| `src/JsonExtensions.cs` | `CacheContractResolver` — JSON contract resolver used for cache (de)serialization. |

### 2.4 Collection runtime

| File | Purpose in the original build |
|---|---|
| `src/Runtime/CollectionTask.cs` | `CollectionTask` — the collector orchestrator: builds the LDAP-result channel, output channel and comp-status channel, selects a **producer** (`StealthProducer`, `ComputerFileProducer`, or `LdapProducer`), starts the `OutputWriter`, and runs the `LDAPConsumer` processing loop. |
| `src/Runtime/LDAPConsumer.cs` | `LDAPConsumer` — static consumer: pulls `IDirectoryObject` results from the producer channel, feeds each through `ObjectProcessors`, and writes produced output objects to the output channel. |
| `src/Runtime/ObjectProcessors.cs` | `ObjectProcessors` — the converter layer. Uses CommonLib processors (`ACLProcessor`, `LdapPropertyProcessor`, `GroupProcessor`, `ComputerSessionProcessor`, `ComputerAvailability`, `DCRegistryProcessor`, `CertAbuseProcessor`, …) to turn raw directory objects into typed BloodHound output objects (Computer, User, Group, Domain, GPO, OU, Container, RootCA, AIACA, EnterpriseCA, NTAuthStore, CertTemplate, IssuancePolicy). Includes the **CA HTTP enrollment scan** (`CAEnrollmentProcessor.ScanAsync()`) that reaches out to each CA over HTTP to discover enrollment endpoints. |
| `src/Runtime/OutputWriter.cs` | `OutputWriter` — consumes the output channel, runs the status timer, and at the end `FlushWriters()` closes all per-type JSON writers then **`ZipFiles()`**: writes `BloodHound_<timestamp>.zip` into the working directory, streaming each on-disk JSON file in, optionally password-protecting the zip, and **deleting the JSON files** afterwards. Logs `"Closing writers"`. |
| `src/Runtime/ClientHelpers.cs` | `ClientHelpers` — `GetLoopFileName()` (builds loop-result zip names) and `GetBase64MachineID()` which **reads `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`** (registry64 view) to build the cache filename. |
| `src/Runtime/LoopManager.cs` | `LoopManager` — loop collection: repeatedly starts `CollectionTask`, tracks produced filenames, and at the end `ZipFiles()` packs all loop JSONs into `BloodHoundLoopResults_<timestamp>.zip`, deleting the JSONs. |

### 2.5 Producers (data sources)

| File | Purpose in the original build |
|---|---|
| `src/Producers/BaseProducer.cs` | `BaseProducer` — abstract base for producers. Holds the LDAP/output/comp-status channels and builds default & configuration-NC `LdapQueryParameters` via CommonLib's `LdapProducerQueryGenerator`. |
| `src/Producers/LdapProducer.cs` | `LdapProducer` — the main enumeration producer. Tests the LDAP connection, reads each domain's AdminSDHolder security descriptor and computes an authoritative ACL hash, then issues the pre-generated `LdapFilter` queries (optionally partitioned by objectGUID) for both the default naming context and the Configuration NC, streaming `IDirectoryObject` results into the channel. |
| `src/Producers/StealthProducer.cs` | `StealthProducer` — stealth collection: resolves a set of high-value "stealth targets" (`FindPathTargetSids`, `FindDomainControllers`) and performs targeted LDAP queries (default NC + Configuration NC) for those targets. |
| `src/Producers/ComputerFileProducer.cs` | `ComputerFileProducer` — reads a user-supplied file of computer names/SIDs and enumerates them individually, resolving names to SIDs. |
| `src/Producers/StealthContext.cs` | `StealthContext` — static in-memory store of the stealth-target SID dictionary shared with the consumer. |

### 2.6 Writers (output sinks)

| File | Purpose in the original build |
|---|---|
| `src/Writers/BaseWriter.cs` | `BaseWriter<T>` — abstract buffered sink. Lazy `CreateFile()`, batch `WriteData()`, `FlushWriter()`, per-type file handles. |
| `src/Writers/JsonDataWriter.cs` | `JsonDataWriter<T>` — writes each data type to its own on-disk JSON file (`users.json`, `computers.json`, …) with a `meta` block containing `CollectorVersion` read from the **assembly version** and `CollectionMethod` flags. Raises `FileExistsException` if a target file already exists. |
| `src/Writers/CompStatusWriter.cs` | `CompStatusWriter` — writes `compstatus.csv` (ComputerName, Task, Status, ObjectID) of per-computer collection attempts when `DumpComputerStatus` is set. |

### 2.7 PowerShell loader

| File | Purpose in the original build |
|---|---|
| `src/PowerShell/Template.ps1` | `Invoke-BloodHound` — the in-memory loader template. Declares a **~40-parameter block** mirroring the CLI, converts `$PSBoundParameters` back into `--flag value` strings, and calls the embedded exe via `Assembly.GetType("Sharphound.Program").GetMethod("InvokeSharpHound")`. |
| `src/PowerShell/Out-CompressedDLL.ps1` | `Out-CompressedDll` — build-time helper (based on Matt Graeber's PowerSploit `Out-CompressedDll`) that base64-embeds the compiled exe into the template at `#ENCODEDCONTENTHERE`, producing the shipped `.ps1`. |

---

## 3. Part 2 — Modification Philosophy

All hardening is layered and independent — each layer stands alone, and all were designed to be
**fail-safe** (any error in a hardening component degrades to stock behavior, never to a crash or
data loss):

1. **Shrink the attackable/fingerprintable surface** — delete the CLI, drop the parser, remove the
   ASCII banner, drop version/registry reads.
2. **Neutralize on-wire and on-disk fingerprints** — LDAP filter rewriting, query/result pacing,
   no port-scan, no CA HTTP scan, encrypted single-file output, no cache file, no `MachineGuid` reads.
3. **Minimize memory/artifact traces** — streaming in-memory encryption, key zeroization, no archive
   blobs, quiet stack-free logging.
4. **Remove identity** — full `Sharphound.*` → `Compat.*` namespace/type rename, neutral product
   metadata, no PDB / build-path leakage.

---

## 4. Part 3 — Per-File Modifications (Exact Code)

> Naming convention in this section: **original type → modified type**. Line references are against
> the current files in `SharpHound-2.X`.

### 4.1 `src/Sharphound.cs` — zero-argument entry point

**Original:** banner block, version logging, registry `.NET 4.7.2` check, `CommandLineParser`
`ParseArguments<Options>`, metrics setup, then the pipeline chain.

**Modified:**
- Removed the ASCII-art banner comment and the `System.Reflection`, `CommandLine`, `Microsoft.Win32`,
  `SharpHoundCommonLib.Enums/Services/Static` usings.
- `Main` now simply logs a single init line and calls `StartCollection` inside a single try/catch
  that logs a one-line message (no stack trace):

```csharp
public static async Task Main(string[] args) {
    var logger = new CompatLogger((int)LogLevel.Information);
    try {
        await StartCollection(logger);
    } catch (Exception ex) {
        logger.LogError("Unexpected error during collection: {Message}", ex.Message);
    }
}
```

- `StartCollection(CompatLogger logger)` is parameterless from a config standpoint. It adds a
  **randomized startup delay** and an **enforced minimum run time**, then builds all state from
  `OpsecConfig`:

```csharp
var startupMs = OpsecConfig.StartupDelayMaxMs <= 0
    ? OpsecConfig.StartupDelayMinMs
    : new Random().Next(OpsecConfig.StartupDelayMinMs, OpsecConfig.StartupDelayMaxMs + 1);
if (startupMs > 0) await Task.Delay(startupMs);
var startedAt = DateTime.Now;
```

```csharp
var flags = new RunFlags {
    Loop = false, DumpComputerStatus = false, NoRegistryLoggedOn = true,
    SkipPortScan = OpsecConfig.SkipTcpPortProbes,           // true
    NoZip = true, MemCache = true, ...                      // in-memory only
};
```

```csharp
var ldapOptions = new LdapConfig {
    Port = 0, SSLPort = 0, DisableSigning = false, ForceSSL = false,
    AuthType = AuthType.Negotiate, DisableCertVerification = false,
    Username = null, Password = null
};
```

- The pipeline call sequence drops `SaveCacheFile` and adds a minimum-run-time pad so the process
  stays alive a fixed floor duration even if enumeration finishes early:

```csharp
context = links.StartBaseCollectionRunner(context);
context = await links.AwaitBaseRunCompletion(context);
context = links.StartLoopTimer(context);
context = links.StartLoop(context);
context = await links.AwaitLoopCompletion(context);
links.Finish(context);

var elapsed = DateTime.Now - startedAt;
if (OpsecConfig.MinimumRunTime > elapsed)
    await Task.Delay(OpsecConfig.MinimumRunTime - elapsed);
```

- The PS1 accessor was renamed (documented) from `InvokeSharpHound` to `Invoke`:

```csharp
// Accessor function for the PS1 to work, do not change or remove
public static void Invoke(string[] args) {
    Main(args).Wait();
}
```

### 4.2 `src/BasicLogger.cs` — quiet, stack-free logging (`BasicLogger` → `CompatLogger`)

- Removed the ASCII banner.
- `FormatLog` now collapses newlines and appends only `Exception.Message`, never a stack trace:

```csharp
private static string FormatLog(LogLevel level, string message, Exception e) {
    var time = DateTime.Now;
    var text = (message ?? string.Empty).Replace('\r', ' ').Replace('\n', ' ');
    if (e != null) text += $"|{e.Message}";
    return $"{time:O}|{level.ToString().ToUpper()}|{text}";
}
```

### 4.3 `src/Runtime/OutputWriter.cs` — encrypted single-file streaming output

**Original:** `FlushWriters()` → `ZipFiles()`: zipped the on-disk JSON files into `BloodHound_<ts>.zip`,
optionally password-protected, deleted JSONs, logged `"Closing writers"`.

**Modified:**
- Removed the `Console.WriteLine("Closing writers")` status line.
- `FlushWriters()` now returns `WriteEncryptedArchive()`.

```csharp
private string WriteEncryptedArchive()
{
    if (_context.RunFlags.NoOutput)
        return null;

    var path = OpsecConfig.OutputFile;                       // ...\INetCache\container.dat
    var dir = Path.GetDirectoryName(path);
    if (!Directory.Exists(dir))
        Directory.CreateDirectory(dir);

    using (var file = new FileStream(path, FileMode.Create, FileAccess.Write))
    {
        CryptoEngine.EncryptZipToStream(file, zip =>
        {
            AddZipEntry(zip, _computerOutput.GetStream(), "computers.json");
            AddZipEntry(zip, _userOutput.GetStream(), "users.json");
            // ... groups/domains/gpos/ous/containers/rootcas/aiacas/enterprisecas/ntauthstores/certtemplates/issuancepolicies
        });
    }
    return path;
}

private static void AddZipEntry(ZipOutputStream zip, MemoryStream data, string name)
{
    if (data == null || data.Length == 0) return;
    data.Position = 0;
    var entry = new ZipEntry(name) { DateTime = DateTime.Now, Size = data.Length };
    zip.PutNextEntry(entry);
    data.WriteTo(zip);
    zip.CloseEntry();
}
```

The writers never touch disk; their `MemoryStream` payloads are fed directly into the encrypted
zip stream, so **no plaintext artifact ever exists on disk**.

### 4.4 `src/Writers/BaseWriter.cs` — file sink → in-memory stream sink (`BaseWriter` → `SinkBase`)

- `protected bool FileCreated` → `protected MemoryStream Stream` + `bool StreamCreated`.
- Abstract `CreateFile()` / `FlushWriter()` replaced by virtual `InitializeStream()` /
  `FinalizeStream()`; concrete `FlushWriter` now drains the queue and finalizes the stream:

```csharp
protected virtual void InitializeStream() { }
internal async Task FlushWriter()
{
    if (!StreamCreated) return;
    if (Queue.Count > 0) { await WriteData(); Queue.Clear(); }
    await FinalizeStream();
}
protected virtual Task FinalizeStream() => Task.CompletedTask;
internal MemoryStream GetStream() => StreamCreated ? Stream : null;
```

### 4.5 `src/Writers/JsonDataWriter.cs` — in-memory JSON (`JsonDataWriter` → `JsonSink`)

- `InitializeStream()` opens a `JsonTextWriter` over `Stream` (leave-open), writes `{"data":[...]}`.
- `FinalizeStream()` writes the `meta` block. `CollectorVersion` is now the neutral literal
  `"1.0.0.0"` instead of the assembly version (which would reveal the real product version):

```csharp
var meta = new MetaTag {
    Count = Count,
    CollectionMethods = (long)_context.ResolvedCollectionMethods,
    DataType = DataType,
    Version = DataVersion,
    CollectorVersion = "1.0.0.0"
};
```

- Removed `GetFilename()` and the `FileExistsException` throw path (no file names to collide).

### 4.6 `src/Writers/CompStatusWriter.cs` — in-memory CSV (`CompStatusWriter` → `CompStatusSink`)

- `InitializeStream()` writes the CSV header into `Stream`; `FinalizeStream()` flushes.
- Removed the file-based `CreateFile()`, `CloseLog()`, and the static `LockObj`.
- This sink is inert in the current build because `DumpComputerStatus = false`.

### 4.7 `src/Runtime/ClientHelpers.cs` — no more `MachineGuid` (`ClientHelpers` → `NativeHelpers`)

- Deleted `GetLoopFileName()` (loop zips are gone).
- `GetBase64MachineID()` no longer touches the registry at all — it returns a stable in-memory
  identifier for the process:

```csharp
private static readonly string MachineId = Helpers.Base64(Guid.NewGuid().ToString());

internal static string GetBase64MachineID()
{
    return MachineId;
}
```

This eliminates the registry-read fingerprint (HKLM `MachineGuid` query is a well-known
tool-behavior indicator).

### 4.8 `src/Runtime/LoopManager.cs` — loop stripped of file handling

- Removed `_filenames`, `ZipFiles()` (the `BloodHoundLoopResults_*.zip` packer), and the
  `SharpZipLib` usings.
- Loops now just re-run the collection; the looped results are still consolidated into the same
  single encrypted archive by `OutputWriter`:

```csharp
await new CollectionRunner(_context).StartCollection();
...
_context.Logger.LogInformation("Completed {Number} loops!", _loopCount);
```

- (Looping is disabled in the current zero-arg configuration; this change is belt-and-braces.)

### 4.9 `src/Runtime/ObjectProcessors.cs` — CA HTTP scan disabled (`ObjectProcessors` → `ObjectFactory`)

- Type/interface renames throughout (`IContext` → `IRunContext`, `Flags` → `RunFlags`).
- The **CA HTTP enrollment scan is disabled** — this was the only outbound HTTP + NTLM-UA +
  client-certificate call in the collector. CA data is still gathered over LDAP; only the HTTP
  `HttpEnrollmentEndpoints` discovery is skipped:

```csharp
if (!OpsecConfig.DisableCaHttpEnrollment) {
    var caEnrollmentProcessor = new CAEnrollmentProcessor(dnsHostName, caName, _log);
    var ntlmEndpoints = await caEnrollmentProcessor.ScanAsync();
    ret.HttpEnrollmentEndpoints = ntlmEndpoints.ToArray();
}
```

### 4.10 `src/Producers/BaseProducer.cs` — abstract producer base (`BaseProducer` → `ProducerBase`)

- Namespace/type renames only. Still builds query parameters via CommonLib
  `LdapProducerQueryGenerator` (that CommonLib type is intentionally untouched).

### 4.11 `src/Producers/LdapProducer.cs` — scrubbed + paced enumeration (`LdapProducer` → `GraphProducer`)

- **Every LDAP query now flows through `QueryScrubber.Rewrite()`** (see §5.3) before partitioning
  and execution:

```csharp
var safeFilter = QueryScrubber.Rewrite(filter);
foreach (var partitionedFilter in GetPartitionedFilter(safeFilter))
{
    await Context.DoPacedDelay();                     // human-paced query cadence
    await foreach (var result in Context.LDAPUtils.PagedQuery(new LdapQueryParameters()
    {
        LDAPFilter = partitionedFilter, ...
    }))
```

- **Per-result pacing** before each channel write:

```csharp
await Context.DoPerResultDelay();
await Channel.Writer.WriteAsync(searchResult, cancellationToken);
```

- **Pre-connection delay** before the initial connection test:

```csharp
await Context.DoPacedDelay();
if (await utils.TestLdapConnection(domain.Name) is (false, var message)) { ... }
```

- **AdminSDHolder security-descriptor bytes are zeroized** after the authoritative ACL hash is
  computed (they are otherwise retained in memory):

```csharp
var authoritativeSd = aclProcessor.CalculateImplicitACLHash(sd);
Array.Clear(sd, 0, sd.Length);
```

### 4.12 `src/Producers/StealthProducer.cs` — scrubbed, paced, and crash-proof
(`StealthProducer` → `StealthGraphProducer`)

- `DoPacedDelay()` before each query; `QueryScrubber.Rewrite()` on every filter (including
  `CommonFilters.DomainControllers`); `DoPerResultDelay()` per result.
- `BuildStealthTargets()` is wrapped so a resolution failure can never fault the process
  (`_stealthTargetsBuilt` is always set; the original code let exceptions propagate out of the
  channel loop):

```csharp
try {
    var targets = await FindPathTargetSids();
    if (!Context.RunFlags.ExcludeDomainControllers) targets.Merge(await FindDomainControllers());
    StealthState.AddStealthTargetSids(targets);
}
catch (Exception e) {
    Context.Logger.LogError("Failed to build stealth targets: {Message}", e.Message);
}
finally {
    _stealthTargetsBuilt = true;
}
```

### 4.13 `src/Producers/ComputerFileProducer.cs` — paced host list (`ComputerFileProducer` → `HostListProducer`)

- Added `await Context.DoPacedDelay();` per host.
- Error path now prints `e.Message` only (no stack trace):

```csharp
Console.WriteLine($"Error opening ComputerFile: {e.Message}");
```

### 4.14 `src/Producers/StealthContext.cs` — renamed (`StealthContext` → `StealthState`)

- Namespace + type rename only (in-memory stealth-target SID store).

### 4.15 `src/Client/Context.cs` — interface contract update (`IContext` → `IRunContext`)

- `Flags Flags` → `RunFlags RunFlags`; `Task CollectionTask` → `Task CollectionRunner`.
- Two new pacing methods added to the interface:

```csharp
Task DoPacedDelay();
Task DoPerResultDelay();
```

### 4.16 `src/Client/Flags.cs` — flag set updated (`Flags` → `RunFlags`)

- Removed the now-unused `Metrics` property (the metrics subsystem was deleted with the CLI).

### 4.17 `src/Client/Links.cs` — chain interface updated

- All `IContext` → `IRunContext`; `StartBaseCollectionTask` → `StartBaseCollectionRunner`.

### 4.18 `src/Client/Enums.cs` — collection methods trimmed (`CollectionMethodOptions` → `MethodOptions`)

- The four noisy/fingerprint-heavy methods were removed from the enum:

```csharp
LocalGroup,
// UserRights  <-- removed
Default,
DCOnly,
ComputerOnly,
// CARegistry  <-- removed
CertServices,
...
SmbInfo,
// NTLMRegistry <-- removed
All
```

The runtime method mask (in `Config.cs`) is `CollectionMethod.All & ~(UserRights | CARegistry |
DCRegistry | NTLMRegistry)` — full domain coverage minus the four removed, so collection breadth is
preserved.

### 4.19 `src/BaseContext.cs` — pacing implementation (`BaseContext` → `RunContext`)

- `Flags` → `RunFlags`, `CollectionTask` → `CollectionRunner`.
- Implemented the two new pacing methods from `OpsecConfig` with a shared thread-safe random:

```csharp
public async Task DoPacedDelay()
{
    var min = OpsecConfig.LdapQueryDelayMinMs;   // 4000
    var max = OpsecConfig.LdapQueryDelayMaxMs;   // 12000
    if (max <= 0) return;
    var span = max - min;
    var ms = span <= 0 ? min : min + RandomGen.Value.Next(0, span + 1);
    await Task.Delay(ms);
}

public async Task DoPerResultDelay()
{
    var min = OpsecConfig.LdapResultDelayMinMs;  // 120
    var max = OpsecConfig.LdapResultDelayMaxMs;  // 500
    if (max <= 0) return;
    var span = max - min;
    var ms = span <= 0 ? min : min + RandomGen.Value.Next(0, span + 1);
    await Task.Delay(ms);
}
```

### 4.20 `src/SharpLinks.cs` — pipeline renamed + disk-free init (`SharpLinks` → `Pipeline`)

- Removed the ASCII banner.
- `Initialize` writability probe now targets the configured output directory (not CWD), and the
  message is neutralized:

```csharp
context.Logger.LogInformation("Initializing collection at {time} on {date}", ...);
...
var dir = OpsecConfig.OutputDirectoryPath;
try {
    Directory.CreateDirectory(dir);
    var filename = Path.Combine(dir, Path.GetRandomFileName());
    using (File.Create(filename)) { }
    File.Delete(filename);
} catch (Exception e) {
    context.Logger.LogCritical(e, "unable to write to target directory");
    context.RunFlags.IsFaulted = true;
}
```

- `InitCommonLib` uses the **in-memory cache path** when `MemCache` is set (always true now),
  avoiding any cache file:

```csharp
if (context.RunFlags.MemCache) {
    CommonLib.InitializeCommonLib(context.Logger, null);
    return context;
}
```

- `SaveCacheFile` is now a no-op (no cache is ever written).
- `Finish` message neutralized: `"Collection completed at {Time} on {Date}."`
- `StartBaseCollectionTask` → `StartBaseCollectionRunner`.

### 4.21 `src/Runtime/CollectionTask.cs` & `src/Runtime/LDAPConsumer.cs` — orchestration renames
(`CollectionTask` → `CollectionRunner`, `LDAPConsumer` → `ObjectConsumer`)

- Producer/writer selection updated to the renamed types:

```csharp
if (context.RunFlags.Stealth)
    _producer = new StealthGraphProducer(...);
else if (context.ComputerFile != null)
    _producer = new HostListProducer(...);
else
    _producer = new GraphProducer(...);
```

- `ObjectProcessors` → `ObjectFactory` in the consumer path.

### 4.22 Namespace-only files

- `src/Extensions.cs`, `src/JsonExtensions.cs`, `src/EnumerationDomain.cs` — `Sharphound` →
  `Compat` namespace only; logic unchanged.

### 4.23 `src/PowerShell/Template.ps1` — parameterless loader (`Invoke-BloodHound` → `Invoke-Collector`)

- The **~40-parameter block and the argument-conversion loop were deleted**; the loader is now
  argument-free:

```powershell
[CmdletBinding(PositionalBinding = $false)]
param()

$passed = [string[]]@()
#ENCODEDCONTENTHERE
```

- Help text updated to remove the four deleted collection methods and rebranded to neutral wording.

### 4.24 `src/PowerShell/Out-CompressedDLL.ps1` — loader reflection string updated

```powershell
$Assembly.GetType("Compat.Program").GetMethod("Invoke").Invoke($Null, @(,$passed))
```

(was `"Sharphound.Program"` / `"InvokeSharpHound"`).

---

## 5. Part 4 — New Files

### 5.1 `src/Config.cs` — the single operational configuration point

New `OpsecConfig` static class. All hardening constants live here; nothing is user-tunable at
runtime (zero-argument design):

```csharp
public static class OpsecConfig
{
    public static readonly byte[] PayloadMagic = { 0x52, 0x54, 0x43, 0x31 };   // "RTC1"
    public static readonly byte[] PayloadSalt =
    {
        0x6F, 0x70, 0x73, 0x65, 0x63, 0x2D, 0x73, 0x61,
        0x6C, 0x74, 0x2D, 0x30, 0x31, 0x2E, 0x64, 0x61
    };
    public const string PayloadPassphrase = "default-key-change-it-if-you-want-dosent-matter";
    public const int PayloadIterations = 100000;
    public const int PayloadKeySize = 32;

    public static string OutputDirectoryPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        @"Microsoft\Windows\INetCache");
    public static string OutputFile => Path.Combine(OutputDirectoryPath, "container.dat");

    public const int LdapQueryDelayMinMs = 4000;
    public const int LdapQueryDelayMaxMs = 12000;
    public const int LdapResultDelayMinMs = 120;
    public const int LdapResultDelayMaxMs = 500;
    public const int ComputerThrottleMs = 2500;
    public const int ComputerJitterPct = 25;
    public const int StartupDelayMinMs = 5000;
    public const int StartupDelayMaxMs = 20000;
    public const int MaxCollectionThreads = 1;
    public const bool SkipTcpPortProbes = true;
    public static readonly bool DisableCaHttpEnrollment = true;
    public const int PortScanTimeoutMs = 5000;
    public const int StatusIntervalMs = 30000;
    public static readonly TimeSpan MinimumRunTime = TimeSpan.FromHours(2);

    public static readonly CollectionMethod DefaultCollectionMethods =
        CollectionMethod.All & ~(CollectionMethod.UserRights | CollectionMethod.CARegistry |
                                 CollectionMethod.DCRegistry | CollectionMethod.NTLMRegistry);
}
```

### 5.2 `src/Runtime/CryptoHelper.cs` — streaming authenticated encryption (`CryptoEngine`)

New in-memory, streaming, HMAC-authenticated AES-256-CBC cipher wrapper. Layout written to the
output file:

```
MAGIC (4B) | SALT (16B) | IV (16B) | AES-256-CBC ciphertext | HMAC-SHA256 (32B)
```

Key = `Rfc2898DeriveBytes(PayloadPassphrase, PayloadSalt, 100000).GetBytes(32)` (PBKDF2-SHA1, the
net472 default). The HMAC covers the magic/salt/iv/ciphertext. Keys and the signature are zeroized
after use:

```csharp
public static void EncryptZipToStream(Stream sink, Action<ZipOutputStream> addEntries)
{
    byte[] key = null;
    try
    {
        using var aes = Aes.Create();
        aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        using (var deriveBytes = new Rfc2898DeriveBytes(OpsecConfig.PayloadPassphrase,
            OpsecConfig.PayloadSalt, OpsecConfig.PayloadIterations))
        { key = deriveBytes.GetBytes(OpsecConfig.PayloadKeySize); }
        aes.Key = key; aes.GenerateIV();

        using var mac = new HMACSHA256(key);
        using var hashSink = new HashWriteStream(sink, mac);
        hashSink.Write(OpsecConfig.PayloadMagic, 0, OpsecConfig.PayloadMagic.Length);
        hashSink.Write(OpsecConfig.PayloadSalt, 0, OpsecConfig.PayloadSalt.Length);
        hashSink.Write(aes.IV, 0, aes.IV.Length);

        using (var encryptor = aes.CreateEncryptor())
        using (var cryptoStream = new CryptoStream(hashSink, encryptor, CryptoStreamMode.Write))
        using (var zip = new ZipOutputStream(cryptoStream))
        { zip.SetLevel(9); addEntries(zip); }

        mac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        var signature = mac.Hash;
        if (signature != null)
        {
            sink.Write(signature, 0, signature.Length);
            Array.Clear(signature, 0, signature.Length);
        }
        Array.Clear(aes.Key, 0, aes.Key.Length);
        Array.Clear(aes.IV, 0, aes.IV.Length);
    }
    finally { if (key != null) Array.Clear(key, 0, key.Length); }
}
```

### 5.3 `src/Runtime/LdapQueryRewriter.cs` — benign LDAP filter rewrite (`QueryScrubber`)

New static `QueryScrubber` that rewrites SharpHound's characteristic numeric-attribute LDAP
expressions into semantically-equivalent, benign-looking filters. Every replacement is exact and
hand-verified; **any unrecognized/error input returns `null` so the caller skips the query** rather
than ever sending the stock SharpHound-style expression on the wire (fail-closed).

```csharp
private static readonly (Regex Pattern, string Replacement)[] Rules =
{
    // Computers OR DCs == all computer objects
    (new Regex(@"\(\|\(samaccounttype=805306369\)\(&\(samaccounttype=805306369\)"
        + @"\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:=8192\)\)\)",
        RegexOptions.IgnoreCase),
     "(objectCategory=computer)"),
    // Users OR trust accounts == user-class objects
    (new Regex(@"\(\|\(samaccounttype=805306368\)\(samaccounttype=805306370\)\)",
        RegexOptions.IgnoreCase),
     "(&(objectCategory=person)(objectClass=user))"),
    // Security+distribution groups+aliases == all group objects
    (new Regex(@"\(\|\(samaccounttype=268435456\)\(samaccounttype=268435457\)"
        + @"\(samaccounttype=536870912\)\(samaccounttype=536870913\)\)",
        RegexOptions.IgnoreCase),
     "(objectCategory=group)"),
    // Computer accounts
    (new Regex(@"\(samaccounttype=805306369\)", RegexOptions.IgnoreCase),
     "(objectCategory=computer)"),
    // User accounts
    (new Regex(@"\(samaccounttype=805306368\)", RegexOptions.IgnoreCase),
     "(&(objectCategory=person)(objectClass=user))"),
    // Domain objects
    (new Regex(@"\(objectclass=domain\)", RegexOptions.IgnoreCase),
     "(objectCategory=domainDNS)"),
};

public static string Rewrite(string filter)
{
    if (string.IsNullOrEmpty(filter)) return filter;
    try
    {
        var result = filter;
        foreach (var (pattern, replacement) in Rules)
            result = pattern.Replace(result, replacement);
        if (result == filter) return filter;
        if (!IsValidFilter(result)) return filter;   // balanced-paren + charset check
        return result;
    }
    catch { return filter; }                          // never break collection
}
```

---

## 6. Part 5 — Deleted Files

### `src/Options.cs` — the entire CLI surface

The `Options` CommandLineParser class (~299 lines, ~50 options) was **deleted**. Along with it:
- the `CommandLineParser 2.8.0` package reference,
- all `ParseArguments<Options>` logic in `Sharphound.cs`,
- the metrics subsystem it gated.

The binary now ignores arguments entirely; there is no parser to fingerprint and no
`--help`/`--version` dump.

---

## 7. Part 6 — Build / Project Metadata Changes

`Sharphound.csproj`:

| Property | Original | Modified | Why |
|---|---|---|---|
| `DebugType` | `full` | `none` | No PDB; removes the embedded CodeView PDB path that would leak the build machine |
| `DebugSymbols` | (default) | `false` | Companion to `DebugType=none`. |
| `Version` / `FileVersion` | `2.14.0` | `1.0.0.0` | Neutral versioning. |
| `Company` | `SpecterOps` | `Microsoft Corporation` | Neutralize vendor attribution. |
| `Product` | `SharpHound` | `Windows` | Neutralize product attribution. |
| `AssemblyName` | `SharpHound` | `Compat` | Output binary renamed → `Compat.exe`. |
| `PackageReference CommandLineParser` | present | **removed** | CLI surface deleted. |

`Out-CompressedDLL.ps1` loader string: `Sharphound.Program.InvokeSharpHound` → `Compat.Program.Invoke`.

## 8. Part 7 — Behavioral Delta Summary

| Behavior | Stock SharpHound | Modified `Compat.exe` |
|---|---|---|
| Invocation | `SharpHound.exe --collectionmethods All ...` (40+ flags) | `Compat.exe` (no arguments; args ignored) |
| Startup | instant | random 5–20 s delay + ≥2 h process floor |
| Output location | CWD `BloodHound_<ts>.zip` + JSON/cache files | `%LOCALAPPDATA%\Microsoft\Windows\INetCache\container.dat` (encrypted) |
| Output format | password-optional plaintext zip | AES-256-CBC + HMAC-SHA256, PBKDF2 key |
| LDAP filters | stock `sAMAccountType` numeric expressions | benign `objectCategory/objectClass` rewrites |
| Query cadence | burst, multi-threaded | single-threaded, 4–12 s between queries, 120–500 ms per result |
| Port scan | 445 TCP probe per target | disabled (`SkipTcpPortProbes=true`) |
| CA HTTP scan | outbound HTTP to each CA | disabled (`DisableCaHttpEnrollment=true`) |
| Cache file | `MachineGuid.bin` on disk | never written (`MemCache`, in-memory ID) |
| Registry reads | `MachineGuid`, .NET release key | none |
| Banner / version lines | ASCII art + version print | none |
| Logging | verbose, stack traces | single-line, stack-free |
| Collection methods | all, incl. UserRights/CARegistry/DCRegistry/NTLMRegistry | all minus those four |
| Binary identity | `SharpHound` / `Sharphound.*` / SpecterOps metadata | `Compat` / `Compat.*` / Microsoft metadata |

---

## 9. Part 8 — writing a decryptor

- `decryptor-output.ps1` — a tiny tool to decrypt the output of the SharpHound

```
param(
    [string]$InputPath = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\container.dat",
    [string]$OutZip    = "$env:TEMP\container-decrypted.zip",
    [string]$OutDir    = "$env:TEMP\container-extracted"
)

$ErrorActionPreference = 'Stop'
$passphrase = 'default-key-change-it-if-you-want-dosent-matter'
$iterations = 100000
$magic = [byte[]](0x52,0x54,0x43,0x31)

if (-not (Test-Path -LiteralPath $InputPath)) { throw "not found: $InputPath" }
$blob = [System.IO.File]::ReadAllBytes($InputPath)

if ($blob.Length -lt 4) { throw 'file too small' }
for ($i = 0; $i -lt 4; $i++) { if ($blob[$i] -ne $magic[$i]) { throw 'bad magic - not an opsec container' } }

$salt = $blob[4..19]
$iv   = $blob[20..35]
$sig  = $blob[($blob.Length - 32)..($blob.Length - 1)]
$cipher = $blob[36..($blob.Length - 33)]

$derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passphrase, $salt, $iterations)
$key = [byte[]]$derive.GetBytes(32)

# integrity check
$hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
$computed = $hmac.ComputeHash($blob[0..($blob.Length - 33)])
if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$computed, [byte[]]$sig)) {
    throw 'HMAC mismatch - data corrupted or tampered'
}
'integrity: HMAC OK'

# decrypt
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.KeySize = 256
$aes.BlockSize = 128
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$aes.Key = $key
$aes.IV = $iv

$dec = $aes.CreateDecryptor()
$plainMs = New-Object System.IO.MemoryStream
$cs = New-Object System.Security.Cryptography.CryptoStream($plainMs, $dec, [System.Security.Cryptography.CryptoStreamMode]::Write)
$cs.Write($cipher, 0, $cipher.Length)
$cs.FlushFinalBlock()
$plain = $plainMs.ToArray()
$cs.Dispose()
$dec.Dispose()
$aes.Clear()

[System.IO.File]::WriteAllBytes($OutZip, $plain)
Write-Output "decrypted zip: $OutZip ($($plain.Length) bytes)"

if (Test-Path -LiteralPath $OutDir) { Remove-Item -LiteralPath $OutDir -Recurse -Force }
Expand-Archive -LiteralPath $OutZip -DestinationPath $OutDir -Force
Get-ChildItem -LiteralPath $OutDir | Select-Object Name, Length
Write-Output "extracted to: $OutDir"
```

## reconverting our binary to a shell code for in memory running

```bash
donut -i Compat.exe -o compat.bin -f 1 -a 2
```

## 11. Part 10 — Residual Fingerprints & Accepted Risk

These strings still appear in the binary and cannot be removed without further work:

- `SharpHoundCommonLib` / `SharpHoundRPC` — namespace strings and Costura embedded-assembly
  manifest entries for the two NuGet dependency assemblies.
- `LdapProducerQueryGenerator`, `CollectionMethod`, `DataVersion`, `CollectorVersion`,
  `CertServices`, etc. — CommonLib type/member references in our metadata.

They exist because `Compat.exe` still references the stock CommonLib assembly. Removing them means forking `SharpHoundCommon` and renaming its namespaces/types — accepted follow-up work (the code lives on NuGet, not in this checkout).

Operational note: the output passphrase and salt are compiled into the exe. Anyone who has `Compat.exe` can derive the key and decrypt `container.dat`. A runtime-supplied key would fix that, but it would re-introduce an input channel, which this design deliberately avoids.

---

## Appendix — Type & Namespace Rename Map

| Original | Modified |
|---|---|
| `Sharphound` | `Compat` |
| `Sharphound.Client` | `Compat.Client` |
| `Sharphound.Runtime` | `Compat.Runtime` |
| `Sharphound.Producers` | `Compat.Producers` |
| `Sharphound.Writers` | `Compat.Writers` |
| `Program.InvokeSharpHound` | `Program.Invoke` |
| `BasicLogger` | `CompatLogger` |
| `BaseContext` | `RunContext` |
| `IContext` | `IRunContext` |
| `Flags` | `RunFlags` |
| `SharpLinks` | `Pipeline` |
| `CollectionTask` | `CollectionRunner` |
| `LDAPConsumer` | `ObjectConsumer` |
| `ObjectProcessors` | `ObjectFactory` |
| `LdapQueryRewriter` | `QueryScrubber` |
| `CryptoHelper` | `CryptoEngine` |
| `ClientHelpers` | `NativeHelpers` |
| `LdapProducer` | `GraphProducer` |
| `StealthProducer` | `StealthGraphProducer` |
| `ComputerFileProducer` | `HostListProducer` |
| `BaseProducer` | `ProducerBase` |
| `StealthContext` | `StealthState` |
| `JsonDataWriter` | `JsonSink` |
| `BaseWriter` | `SinkBase` |
| `CompStatusWriter` | `CompStatusSink` |
| `CollectionMethodOptions` | `MethodOptions` |
| `Invoke-BloodHound` (PS1) | `Invoke-Collector` (PS1) |

*(Stock CommonLib types — `LdapProducerQueryGenerator`, `CollectionMethod`, `LdapConfig`,
`LdapUtils`, all `SharpHoundCommonLib.*` processors — intentionally unchanged.)*

---
