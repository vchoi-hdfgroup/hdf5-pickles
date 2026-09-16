# Assert-masked deserializer invariants

**Status: draft, work in progress.** This catalogs GitHub issue #87: places
where a value decoded from untrusted HDF5 file bytes is validated only by
`assert()` — or by ordinary `if (...) HGOTO_ERROR(...)` code wrapped in
`#ifndef NDEBUG` — rather than a real, always-on check. Both mechanisms
disappear identically under `-DNDEBUG`, i.e. in every shipped Release build,
so both count as "assert-masked" here.

Two of the issue's seven named areas are complete (SOHM, Extensible arrays);
the other five (V2 B-trees, Dataset chunk records, Fractal heaps, Free-space
managers, Metadata-cache images) are not yet started. This is a first pass,
not a final document.

## Scope

**In scope:** a check that exists in the source but is defeated by a build
flag (`assert()`, or a `#ifndef NDEBUG` block), validating a value that comes
from untrusted file bytes.

**Out of scope:** asserts on pure internal/programmer state unrelated to file
bytes (caller-supplied pointers, ref-counts, cache-state invariants); sites
where a newer, non-`assert` initialization helper already performs a real,
`NDEBUG`-surviving check; debug-only or test-only code paths not reachable
from an ordinary application opening an untrusted file.

**How findings were verified.** Every finding below claiming a *measured*
consequence was checked by building a real, byte-level fixture — one or two
bytes changed in a valid seed file, its Jenkins-lookup3 checksum resealed —
and then observing both `h5policy`'s verdict and a real libhdf5 build's
actual behavior (timing, memory, and, where useful, the full HDF5 error
stack via a minimal C reproducer). Findings not yet given this treatment are
marked "traced, not yet measured" rather than assumed either way.

## SOHM (`H5SM*.c`, 170 asserts across 5 files — complete)

Every finding below has now been built as a real fixture (one or two bytes
changed in a valid seed, checksum resealed) and measured against both
`h5policy` and a real libhdf5 build — none are "traced only."

| # | Invariant | Root cause | Guard site(s) | Consequence | `h5policy` |
|---|---|---|---|---|---|
| 1 | Table format `version` | `H5Oshmesg.c:87` — raw decode, no check at the decode site itself | `H5SMcache.c:214` | **Measured: inert.** Opens and reads normally — only one version is ever defined and nothing branches on it | Confirmed: dedicated check (`H5_CORRUPT_SOHM_VERSION`) |
| 2 | `num_indexes` bounds | `H5Oshmesg.c:95` — raw decode, no check at the decode site itself | `H5SMcache.c:222`, `H5SM.c:1960` | **Measured: clean file-open failure** — an inflated count sizes the expected master-table read past the file's real end-of-allocation (`addr overflow`), no crash, no memory growth | Confirmed: dedicated check (`H5_CORRUPT_SOHM_INDEX_COUNT`, valid range 1-8) |
| 3 | Message `location` legality | `H5SMmessage.c:312` — raw decode, no check at the decode site itself; only two legal encoded values exist, and a third is never rejected anywhere in the subsystem either | `H5SMmessage.c:227,320`, `H5SM.c:1178,1310,2196,2371`, `H5SMbtree2.c:181` | **Measured: reads unaffected; a write fails.** An illegal value falls into the wrong branch, reinterpreting an in-heap record's bytes as an in-object-header record — genuine type confusion, caught cleanly by an address-vs-end-of-allocation bound | Confirmed: dedicated check (`H5_CORRUPT_SOHM_LOCATION`) |
| 4 | Index `index_type` legality | `H5SMcache.c:247` — raw decode, no check at the decode site itself | `H5SM.c:571,1322,1462,1810,2181,2700` (each silently treats an illegal 3rd value as `BTREE`) | **Measured: reads unaffected; a write fails.** The illegal value falls into the B-tree branch, which then tries to open a *list* structure's address as a v2 B-tree header — genuine type confusion, caught cleanly by a checksum mismatch | Confirmed: dedicated check (`H5_CORRUPT_SOHM_INDEX_TYPE`) |
| 5 | `list_max`/`btree_min` cross-index consistency | `H5SM.c:1984-1985` — decoded independently per index, no cross-check | `H5SM.c:1984-1985` | **Measured: silent misreporting, no functional break.** Built a genuine 2-index file, patched only one index's values (unreachable via any legitimate API call). `H5Fget_create_plist()` silently reports the *other* index's values — the real list↔B-tree conversion logic is unaffected since it reads each index's own values directly | **None — confirmed coverage gap.** `h5policy` accepts the crafted file outright |
| 6 | `msg_type_id` out-of-bounds array index | `H5SMmessage.c:323` — raw decode, indexes a fixed 27-element array with no bound check before the access | `H5SM.c:2343-2344`, `H5Omessage.c:1091` | **Measured, cross-platform (macOS + Linux, stock and ASan builds): the out-of-bounds read genuinely executes on a real, crafted file, and is silent on every build tested** — not because the access is safe, but because (a) ASan's redzones don't cover "wild" far-out-of-bounds reads on small globals, a general sanitizer limitation, not platform-specific, and (b) the one reachable consumer path uses the resulting garbage value only in a pointer-*equality* comparison, never a dereference | Confirmed: dedicated check (`H5_CORRUPT_SOHM_MESSAGE_TYPES`) |

**Also checked, not a vulnerability:** the *within*-index
relationship `num_messages > list_max` (a single index whose message count
already exceeds its own declared capacity) is already properly guarded — a
real, deliberate check in `H5SM__cache_list_verify_chksum`
(`H5SMcache.c:495-496`, `"number of SOHM messages exceeds list size"`), not
masked by anything.

**Note on `h5policy` coverage generally:** five of these six invariants
have a dedicated check, all defined in `h5policy/pickles/h5_sohm.pk` (see
the table for each one's specific code). The sixth, `list_max`/`btree_min`
cross-index divergence (finding #5 above), is a genuine gap: `h5policy`
has no check for it at all and accepts the crafted file outright.

**Recommendation for finding #5 (not implemented here):** unlike the other
five, closing this one needs two separate fixes, not one. On the libhdf5
side, the assert at `H5SM.c:1984-1985` could be promoted to a real,
always-on check that rejects the file at open time when any two indexes'
`list_max`/`btree_min` diverge — safe to do unconditionally, since no
legitimate writer can ever produce a divergent file in the first place. On
the `h5policy` side, that promotion alone would not add coverage: there is
no existing check to strengthen, so closing the gap needs a genuinely new
check in `h5policy/pickles/h5_sohm.pk` for this same cross-index
relationship. Both are deliberately left as recommendations rather than
changes in this PR — worth a maintainer decision on priority and exact
shape before anyone implements them.

## Extensible arrays (`H5EA*.c`, 314 asserts across 11 files — complete)

Two independent, fully-measured severe findings — finding #1 in the table
below (header `nsblks` underflow), and `max_idx_set`, covered separately
under **Adjacent findings** since it isn't literally assert-masked;
everything else across all 11 files reconciles to internal/write-path
checks or an echo of one of these two.

All six `H5EA_create_t` header parameters share one root cause
(`H5EAcache.c:320-328` — raw decode, no check at the decode site itself;
real validation exists only in `H5EA__hdr_create`, `H5EAhdr.c:346-388`,
masked by `#ifndef NDEBUG` and create-path-only in any case), so the table
below lists each field's own measured consequence rather than repeating the
shared root cause for rows 1-5; rows 6-7 are two further candidates found
one level deeper in the call graph, each with its own root-cause site:

| # | Invariant | Root cause | Guard site(s) | Consequence | `h5policy` |
|---|---|---|---|---|---|
| 1 | `max_nelmts_bits` + `data_blk_min_elmts` (→ `hdr->nsblks`) | `H5EAcache.c:320-328` (shared, see above) | `H5EAhdr.c:180-182` (weak, nonzero-only) | **Measured: severe out-of-memory (OOM) denial-of-service (DoS)** — 1 byte changed, 55GB+ RAM, OOM-killed after 22s, ordinary dataset read | Confirmed: dedicated geometry check rejects instantly |
| 2 | `max_dblk_page_nelmts_bits` (→ `dblk_page_nelmts` via `1 << max_dblk_page_nelmts_bits`) | same | `H5EAcache.c:1011,1014,1018,1423` (react after the fact) | Measured: data-loss-on-read (checksum mismatch, no crash) | Confirmed, same check |
| 3 | `sup_blk_min_data_ptrs` | same | — | Measured: data-loss-on-read (checksum mismatch); a cross-field variant (`nsblk_addrs`, computed unguarded at `H5EAiblock.c:113-115` — see row 7) caught by a 3rd, distinct incidental mechanism — see below | Confirmed, same check |
| 4 | `raw_elmt_size` | same | — | Measured: data-loss-on-read (checksum mismatch) | Confirmed, same check |
| 5 | `idx_blk_elmts` | same | — | Measured: data-loss-on-read — checksum mismatch at `0`; addr-overflow at a value that actually violates page capacity | Confirmed directly for a violating value |
| 6 | `H5EA__hdr_alloc_elmts`'s `idx` underflow (one level deeper) | `H5EAhdr.c:245` — no check at this computation site | `H5EAhdr.c:316-317` (sibling `free_elmts` asserts on the same `idx`, elsewhere) | Measured: subsumed by #2's condition, not an independent hazard | n/a — same check already catches the precondition |
| 7 | `H5EA__iblock_alloc`'s `nsblk_addrs` underflow (cross-field, one level deeper) | `H5EAiblock.c:113-115` — zero guard | — | Measured: caught by a 3rd incidental mechanism (`H5C__load_entry` generic length-sanity bound), ~18-exabyte wrap, ~3.5MB peak memory, not independent | Confirmed: dedicated check also covers this relationship |

### Finding #1 in depth — header `nsblks` underflow: severe OOM DoS

`H5EA__hdr_init` (`H5EAhdr.c:185`) computes:

```c
hdr->nsblks = 1 + (hdr->cparam.max_nelmts_bits - H5VM_log2_of2(hdr->cparam.data_blk_min_elmts));
```

If `max_nelmts_bits < log2(data_blk_min_elmts)`, this underflows in unsigned
32-bit arithmetic to a value near 2^32, sizing an `H5FL_SEQ_MALLOC` followed
by a loop that writes every slot.

**Measured:** one byte changed in a 2208-byte valid seed file
(`max_nelmts_bits` 32→1). `h5policy --profile untrusted-strict` rejects it
instantly, zero memory (`H5_CORRUPT_EXTENSIBLE_ARRAY_GEOMETRY`, a
deliberate, comprehensive geometry check covering all six fields and their
cross-relationships). A real build (h5py 3.14.0 / HDF5 1.14.6, arm64 macOS)
opens the file fine, then an *ordinary* `dataset[...]` read causes:

```
maximum resident set size: 5,447,286,784 bytes   (~5.4 GB)
peak memory footprint:    55,473,675,312 bytes   (~55.5 GB)
real time: 22.37s before the process was killed
```

A ~2KB file, one byte changed, no special API calls — just opening a file
and reading a dataset the ordinary way.

**Why #1 alone is severe while #2-#7 are not (the generalized rule, tested
across all seven rows above):** a field's bad value produces a severe
consequence only if its arithmetic stays entirely inside the header's own
already-checksummed structure, as `nsblks` does. Every other row's
corruption instead changes the computed size (or requested read length) of
a *different* metadata block — the index block, in every case tested — and
that block's own independent verification (a checksum, an
address/size-vs-end-of-allocation bound, or the generic cache-load
length-sanity bound behind row #7) catches the mismatch before the bad
arithmetic ever gets a chance to misbehave for real. These are at least
three distinct, independently-confirmed incidental mechanisms, not one, and
none of them is a deliberate defense against this specific bug class —
`h5policy`'s own dedicated geometry check is the only *deliberate* one at
play here.

A separate, non-assert-masked finding (`max_idx_set`) was also found in this
area during the same sweep — see **Adjacent findings**, below.

## Adjacent findings (not literally assert-masked, same danger shape)

### `max_idx_set` — unbounded loop, reachable via a public API, zero `h5policy` coverage

`hdr->stats.stored.max_idx_set` ("highest element index stored, +1") is one
of six *array-statistics* fields in the extensible-array header (a
different family from the six create-time `cparam` fields above) — decoded
raw at `H5EAcache.c:336` with zero validation. Unlike the findings above,
there is no assert or `#ifndef NDEBUG` block guarding it anywhere; it was
simply never checked, on any path, in any build configuration. It directly
bounds a loop with no upper sanity check:

```c
/* H5EA.c:985, H5EA_iterate() */
for (u = 0; u < ea->hdr->stats.stored.max_idx_set && ret_value == H5_ITER_CONT; u++) {
    H5EA_get(ea, u, elmt);
    (*op)(u, elmt, udata);
}
```

This is reachable via an ordinary, documented **public API** —
`H5Dchunk_iter()`, the chunk-introspection call used by h5repack and any
application enumerating a dataset's chunks — backed by
`H5D__earray_idx_iterate` (`H5Dearray.c:1370`), guarded only by
`max_idx_set > 0`.

**Measured:** one 8-byte field changed in a 300-chunk fixture, checksum
resealed. With `max_idx_set = 50,000,000` (bounded, for a clean
measurement), a minimal C reproducer calling `H5Dchunk_iter`:

```
count=300 (all real chunks correctly reported)
1.22s real, ~41 million iterations/second
peak memory footprint: ~5.8MB (flat -- no growth)
```

Pure CPU-time cost, linear in the field's value. Since it's a full 64-bit
field with no ceiling, this scales to an arbitrarily long hang — confirmed
directly with `max_idx_set = 2^35` (~3.4×10^10), which left the same
reproducer pinned at 100% CPU / ~4MB RSS for 1:45 with zero completion
before being stopped. No crash, no memory blowup — the cost is purely the
raw iteration count, since each out-of-range lookup bails out cheaply via an
address-undefined check.

**`h5policy` coverage: none.** `h5policy --profile untrusted-strict`
returns `"decision": "accept", "findings": []` outright on the crafted
file. Unlike every one of the six `cparam` fields above — which `h5policy`
already covers via its own deliberate geometry check — this is a genuine,
currently-undetected gap in this repo's own tooling, not just a masked
libhdf5 check. Traced the other five array-statistics fields
(`nsuper_blks`, `super_blk_size`, `ndata_blks`, `data_blk_size`, `nelmts`)
for comparable hazards: all five are equally unvalidated, but only reached
via write-path increments, debug-dump printing, or one plain addition
reported as a storage-size number — none feeds a loop bound, allocation
size, or array index, so none appears to share this specific hazard.

**Recommendation (not implemented here):** a follow-up `h5policy` check —
something like rejecting a `max_idx_set` that is wildly disproportionate to
what the array's own geometry (`max_nelmts_bits`, `data_blk_min_elmts`,
etc.) could plausibly have populated. This would be a new check in
`h5policy/pickles/h5_chunkindex.pk`, touching tracked repository files, and
is deliberately left as a recommendation rather than a change in this PR —
worth a maintainer decision on priority and exact shape before anyone
implements it.

**Not chased further this session:** whether a single very large targeted
index (rather than iterating up to it) can push `H5EA__dblock_sblk_idx`'s
`sblk_idx` (grows as `log2(idx)`) past `hdr->nsblks`, causing an actual
out-of-bounds heap *read* into `hdr->sblk_info[]` — a structurally
different, and potentially more serious, class of bug than the
CPU-exhaustion DoS above (a memory-safety issue rather than resource
exhaustion), *if* reachable. A bounded iteration test never reached that
threshold; a follow-up attempt via `H5Dget_chunk_info_by_coord()` to query
one index directly itself stalled unexpectedly for 30s+, likely a
different mechanism, not pursued further.

## Status: remaining areas (not started)

| Area | libhdf5 source | Notes |
|---|---|---|
| V2 B-trees | `H5B2*.c` | Existing precedent: `registry/cases/v2-btree-record-size-zero-assert-only.yml` (confirmed x86-64-only SIGFPE; arm64 doesn't trap) |
| Dataset chunk records | `H5Dchunk/btree/btree2/farray/earray/single/none.c` | `chunk-dim-product-64bit-overflow.yml` names one case directly |
| Fractal heaps | `H5HF*.c` (16 files) | Not started |
| Free-space managers | `H5FS*.c` | Not started |
| Metadata-cache images | `H5AC*.c`, cache-image code | Not started |
