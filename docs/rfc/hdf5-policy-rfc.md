# HDF5 Policy RFC — Use Cases and Scope (draft)

> **Draft for review.** This covers the RFC's Introduction, Section 1 (Use
> cases), and Section 2 (Scope and controls inventory). Section 3 (API),
> Section 4 (Implementation and test plan), and Further considerations are still
> to come. The legitimate-use scenarios (§1.2) are stated from each feature's
> documented intent; naming the specific communities that rely on them is
> optional enrichment for later, not a prerequisite.

## Introduction

An HDF5 file can do more than hold data. By design, a well-formed file can
instruct the library — during an ordinary read — to **open other files**,
**reach arbitrary filesystem paths**, or **load and run external code**. These
are intentional, long-standing features: external datasets and external raw
storage, virtual datasets (VDS), external links, the multi/family virtual file
drivers, and dynamically loaded filter / VOL / VFD plugins.

Today the library treats **validity and authorization as the same thing.** If a
file is well-formed, it is automatically authorized to trigger these actions.
So an application that merely *reads a dataset* from an untrusted file can be
made to read `/proc/self/environ`, open `/etc/passwd`, or execute third-party
code — with nothing signalling that a trust boundary was crossed.

That conflation is the root problem. As long as validity implies authorization,
every "should the library do this?" question collapses into "is it a bug or a
feature?" — a debate that cannot be won, because the action is, by design, a
feature. This RFC proposes to **break the link between validation and
authorization.** Validation answers *"is this a well-formed HDF5 file?"*;
authorization — a separate, application-controlled decision — answers *"may this
file cause the library to cross a trust boundary?"* **By default, validity must
authorize nothing.**

The need is not hypothetical: in July 2026 a crafted HDF5 file was the opening
vector of a real intrusion (Section 1). This RFC originates in a maintainer
request to add controls for these cross-file features —
[HDFGroup/hdf5 issue #6618](https://github.com/HDFGroup/hdf5/issues/6618), which
enumerates them and points to that incident. The scope of this RFC is **every
trust-boundary-crossing action a file can induce** — external file access,
filesystem reach, and external code loading.

## 1. Use cases

### 1.1 Risk scenarios — where validity-equals-authorization bites

**Scenario A — Untrusted dataset in an ingest pipeline (the [Hugging Face
incident](https://huggingface.co/blog/agent-intrusion-technical-timeline#vector-1-hdf5-external-raw-storage-file-read),
July 2026).** An attacker committed a dataset to Hugging Face whose
configuration pointed each data "split" at a small, *valid* `.h5` file. Each
file used HDF5 **external raw storage** to declare that its dataset's bytes
lived at a **local filesystem path** on the worker — among them
`/proc/self/environ` and the worker's own source files. When the production
data-loader opened these files and read the datasets, the library transparently
read those local paths and returned their contents as dataset data. The result:
the worker's full environment (the environment variables of its Kubernetes
*pod*) — including secrets and credentials — plus internal source code,
disclosed to the attacker. **No code was executed**; this
was pure file disclosure through a normal read. The platform's URL allowlist,
which governed *network* fetches, never saw it, because external-reference reads
are *local* filesystem operations. This disclosure was the quiet first foothold
of a multi-stage intrusion: the leaked credentials and reconnaissance enabled
the escalation that followed.

**Scenario B — Untrusted file uploaded to a service (the archetype).** A
published proof-of-concept ([h5py issue #2891](https://github.com/h5py/h5py/issues/2891))
crafts an HDF5 file with an
external dataset pointing at `/etc/passwd`. A victim web application accepts the
upload, reads the dataset with default settings, and returns the contents in its
response — disclosing a local file to the attacker. This is the general shape for
any service that parses untrusted HDF5: external datasets, VDS, and external
links each let an uploaded file name a path the server then reads. The h5py
maintainers declined to add enforcement in the binding, noting the fix belongs
in the library.

**Why this is escalating.** These features have existed for years, but the
exposure is growing. Machine-learning (ML) and AI pipelines now routinely ingest
third-party datasets and models, and automated agents probe them at machine
scale — in the Hugging Face case the agent took roughly 17,600 actions, trying
many failing paths and repeatedly returning to leads, turning an ordinary
architectural weakness into a critical one faster than a human attacker could.
Detection-based defenses are the wrong tool for this: parser hardening and fetch
allowlists must anticipate every malformed input or attack path and fail on the
one case they miss — the Hugging Face URL allowlist watched *network* fetches but
not *local* reads, so it never saw the attack. An authorization boundary that
denies *by default* works differently: it needs to recognize nothing, because the
trust-boundary action is simply unavailable to untrusted input unless the
application turns it on. Such a boundary holds no matter how the attack is shaped
or how many probes are thrown at it — so its safety does not depend on the library
catching every parser bug or on defenders foreseeing every probe.

**The common pattern.** Scenarios A and B are not unrelated bugs. They are one
structural shape:

> untrusted file → ordinary read → trust-boundary crossing (external open /
> path reach / code load) → disclosure or code execution

with no authorization checkpoint between "the file is valid" and "the library
acts." Inserting that checkpoint — an authorization decision the application
controls — is what this RFC addresses.

### 1.2 Legitimate-use scenarios — what must keep working

These features exist because real applications use them deliberately. Any
control must let **authorized** callers keep using them; the goal is to deny
them *by default to untrusted input*, not to remove them. Each scenario below
states the feature's **documented intent** — what the format provides it for.

**L1 — External / raw storage wrapping large existing data.** External datasets
and external raw storage (`H5Pset_external`) let a dataset's raw bytes live in
one or more files *outside* the HDF5 container, at application-chosen offsets, so
an application can expose pre-existing large binary arrays — or data still being
produced by another process or instrument — as HDF5 datasets without copying
them in.

**L2 — Virtual datasets stitching many files.** A virtual dataset
(`H5Pset_virtual`) maps regions of several source datasets — typically one file
each — into a single logical dataset through a stored mapping, so many
separately produced files appear as one array without duplicating their bytes.
Its documented purpose includes assembling per-process or time-sequenced output
into one view.

**L3 — External links across a related file set.** An external link
(`H5Lcreate_external`) names an object — a group or dataset — in another HDF5
file by path, so one file can organize or navigate a collection of related
files as a single hierarchy.

**L4 — Splitting one file across members (multi / family VFD).** The family
driver (`H5Pset_fapl_family`) stores one logical HDF5 file as a series of
fixed-size member files, and the multi driver (`H5Pset_fapl_multi`) maps
different kinds of data to separate files — used to keep a file under a
filesystem's size limit, or to transport it in parts.

**L5 — Reading data compressed with third-party codecs (dynamically loaded
filters).** Registered filter plugins (`H5PL`) let the library read and write
data compressed with community codecs — Blosc, Zstd, LZ4, bitshuffle, and
others — distributed as plugins rather than built into the library, so files
using them are readable wherever the plugin is installed.

**What this means for the design.** The design cannot be built around an
allowlist of known-good uses. It must instead **deny by default and fail loudly
and recoverably**, so that an unanticipated legitimate use surfaces as a clear,
fixable error — a denied action with a documented opt-in — rather than as either
a silent security hole or a silent breakage.

### 1.3 Derived requirements — what the design must provide

The scenarios translate into requirements for Sections 2–4:

1. **Application-declared, per-file trust.** Trust is not a property of the file
   and cannot be inferred from its bytes; the application declares it per file
   (an untrusted upload vs. a trusted internal file) and the library enforces
   that declaration. The control must be per-file and must hold for concurrent
   files of differing trust open in one process.
2. **File-reference family — per-action granularity + path confinement.**
   Controls must gate each file-reference action distinctly — external datasets,
   external raw storage, virtual datasets, external links, and the multi/family
   VFD — and, for these, confine *where* a reference may resolve (an allowed
   prefix; denying `/proc`, `/sys`, `/dev`), with care for absolute paths, `..`
   escapes, and symlinks.
3. **Code-execution family — plugin loading as a provenance decision.**
   Dynamically loaded filter / VOL / VFD plugins are the code-execution family:
   the risk is
   running untrusted *code*, so the control is the origin and integrity of that
   code — whether it is trusted to run — not where a path resolves. Path
   confinement does not apply; this action must be gated separately, and is the
   natural meeting point with complementary work on signed plugins.
4. **Practical defaults, and a safe default.** The controls must group into a
   few practical policy defaults (profiles). The default when an application
   declares nothing should move toward "authorize nothing," with a migration
   path that does not break the legitimate uses above.
5. **Fail-safe and visible.** Because the legitimate-use set can never be
   enumerated completely, a denied action must fail *loudly and recoverably* — a
   clear error and a documented opt-in — rather than silently, so an unforeseen
   legitimate use is a fixable breakage, not a silent security hole.
6. **Detectability.** An application should be able to determine whether a file
   would cross a trust boundary — and where — *without* triggering it. This
   echoes a concrete ask from the h5py discussion
   ([h5py issue #2891](https://github.com/h5py/h5py/issues/2891)), where
   maintainers floated a tri-state `obj.internal` property (internal / external /
   unknown) so a caller can check before reading. Detectability here is a
   *complement* to enforcement, not a substitute for it: detection *instead of*
   enforcement — "detect-only," leaving each application to check and act — is a
   weaker alternative, because it protects only applications that remember to
   check, which the motivating incidents did not. It is recorded among the
   alternatives (Further considerations), not adopted as the control.

## 2. Scope and controls inventory

Section 1 established *why* the library must separate validation from
authorization, and *what* the design must provide. This section is the
**supply** side to Section 1's demand: it enumerates, action by action, exactly
what the library controls. For each trust-boundary-crossing action it records
the action, its risk family, the control that gates it, the behavior today, and
the behavior this RFC proposes. The result is an auditable map — a reviewer can
confirm that every action Section 1 raised has a defined control, and that none
is left implicit.

### 2.1 In scope and out of scope

**In scope.** Every action by which a *well-formed* HDF5 file, read with default
settings, causes the library to cross a trust boundary — open another file,
reach a filesystem path, or load and run external code — during normal
operation. These are the actions inventoried in Section 2.2.

**Out of scope** (deliberately excluded; several recur in Further
considerations):

- **Plugin provenance / signature verification.** The plugin-load *action* is in
  scope (Section 2.2); the provenance *control* on it is not — it is a separate
  RFC's concern, not a later phase of this one. This RFC gates plugin loading
  *on or off* — *may any plugin load for this file?* Verifying the
  origin and integrity of the plugin code (signing) — *which* code is trustworthy
  to run — is a separate, complementary control, the subject of the Signed
  Plugins RFC. Provenance layers on top of this on/off authorization gate rather
  than replacing it: a validly signed plugin can still be malicious.
- **Validation and parser hardening.** Detecting malformed or corrupt metadata
  is a separate concern; this RFC governs authorization of *valid* files and
  does not change how invalid files are rejected.
- **Application-selected remote drivers** — the read-only `ros3`
  (`H5Pset_fapl_ros3`, Amazon S3 and S3-compatible stores) and `hdfs`
  (`H5Pset_fapl_hdfs`) VFDs. These are selected by the application through the
  FAPL, not induced by the file, so they are not a file-driven trust-boundary
  crossing. (The multi / family driver *is* in scope, because its member layout
  travels with the file.)
- **Resource-exhaustion and decompression-bomb defenses.** A valid file can be
  crafted to exhaust memory, CPU, or time on read — for example a metadata count
  that drives a huge allocation, or a small compressed chunk that inflates to
  many gigabytes when decompressed (a decompression bomb). Guarding against this
  is a distinct axis — resource budgets and quotas — from authorizing
  trust-boundary actions, and belongs to a separate mechanism.
- **The write path.** This RFC protects a process *reading* an untrusted file;
  an application's own deliberate use of these features when creating files is
  its own choice.

### 2.2 The controls inventory

| Action | Family | Control | Current default | Proposed default (nothing declared) |
|---|---|---|---|---|
| External storage read (a dataset's raw bytes in a separate file) | file-reference | allow / deny + path confinement | allow — because valid | deny; opt-in within a confined path |
| Virtual dataset (VDS) source open | file-reference | allow / deny + path confinement | allow — because valid | deny; opt-in within a confined path |
| External link traversal | file-reference | allow / deny + path confinement | allow — because valid | deny; opt-in within a confined path |
| Multi / family VFD member open | file-reference | allow / deny + path confinement | allow — because valid | deny; opt-in within a confined path |
| Dynamic filter plugin load | code-execution | allow / deny (on/off gate) | allow — because valid | deny; opt-in |
| Dynamic VOL / VFD plugin load | code-execution | allow / deny (on/off gate) | allow — because valid | deny; opt-in |

Three things the table makes explicit:

- **The current default is identical on every row** — *allow, because the file
  is valid.* That uniform column is exactly the validity-equals-authorization
  conflation Section 1 identifies.
- **The proposed default is the behavior when the application declares
  nothing.** The policy profiles (Section 3) adjust these, within the invariant
  that a denied action always fails safe and visibly (Section 1.3, requirements
  4–5), and within a migration path that does not break existing files overnight
  (Further considerations).
- **The control differs by family.** File-reference actions add *path
  confinement* — an allowed prefix, with `/proc`, `/sys`, `/dev` denied and care
  for `..` and symlinks. For code-execution actions this RFC provides only the
  on/off gate; their other axis — *provenance* (which code is trustworthy,
  Section 1.3, requirement 3) — is a complementary control out of scope here
  (Section 2.1). Dynamic VOL / VFD plugin loading shares the legitimate-use
  rationale of filters (Section 1.2, L5); filters are simply the most common
  case.

### 2.3 Actors

Only three parties take part in an authorization decision:

- **The application** declares the per-file trust and policy, through the FAPL,
  at or before open. It is the only party that can know whether a given file is
  trusted.
- **The file** is the subject the policy is applied to — never a trusted source
  of its own authorization. Nothing in its bytes may raise its own privilege.
- **The library** enforces the declared policy at each action's chokepoint and
  reports a denial as a distinct, recoverable error.

This is the concrete form of Section 1.3, requirement 1: trust is *declared by
the application and enforced by the library, never inferred from the file.*
