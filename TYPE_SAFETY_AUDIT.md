# Impacket Type-Safety Audit

## Scope

This audit reviews the Python implementation, examples, and tests for runtime
defects that can be exposed by static type analysis. It does not aim to add
annotations everywhere or make any one checker report zero diagnostics.

Type-checker findings are treated as leads, not proof. A change is made only
when the runtime behavior, protocol contract, or test coverage demonstrates
that the existing code is unsafe or incorrect.

## Audit environment

- Branch: `copilot/type-safety-audit`
- Starting commit: `137441c1545798a13fc234b4aa5232b522cb3507`
- Python source: 341 files and approximately 132,000 code lines
- Core package: 171 files and approximately 95,000 code lines
- Existing typing: no stub files, no `py.typed` marker, and almost no function
  return annotations

## Checker baselines

Baseline results will be recorded after dependencies and checker environments
are established.

| Checker | Version | Scope | Diagnostics | Notes |
|---|---|---|---:|---|
| ty | 0.0.57 | `impacket`, `examples`, `tests` | 4,078 | Down 45; dominated by dynamic-attribute findings |
| Pyright | 1.1.411 | `impacket`, `examples`, `tests` | 5,065 | Down 358; largest useful baseline reduction |
| mypy | 2.2.0 | Untyped function bodies included | 7,482 | Up 9 from added regression code; still the noisiest baseline |

## Highest-impact changes

Entries are ordered by expected reduction in runtime failures, data corruption,
interoperability problems, or security risk. New findings are appended during
the audit and periodically re-ranked.

| Rank | Change | Impact | Evidence | Status |
|---:|---|---|---|---|
| 1 | Send the correct by-reference VARIANT values from `IDispatch.Invoke()` | High: DCOM Automation requests sent reference indexes in place of reference values, corrupting by-reference arguments and out parameters | Local request-construction test uses distinct index and VARIANT objects and verifies both fields | Fixed |
| 2 | Preserve DCOM object identity and reject unsupported OBJREF shapes | High: `dcomexec` copied OXID into the OID field and dereferenced absent structures for unknown/custom OBJREF values | Tests verify distinct OXID/OID forwarding and controlled rejection of unknown types | Fixed |
| 3 | Accept valid jailed paths in SMB `setPathInformation()` | High: the path-jail condition was inverted, so valid in-share path updates were rejected while only the unsafe branch was intended to fail | Unit test drives an in-jail basic-information update through the transaction handler | Fixed |
| 4 | Normalize SMB1 strings before path handling | High: numerous SMB1 file operations passed `bytes` into string path normalization and failed with `TypeError`; pre-decoded text also needs to remain accepted | Tests verify non-Unicode wire bytes decode and existing text is preserved | Fixed |
| 5 | Correct WMI array type identifiers | High: UInt32, SInt64, and UInt64 arrays were assigned unrelated CIM type IDs, including a collision with Boolean arrays | Regression test verifies every array type equals its scalar type combined with `CIM_ARRAY_FLAG` | Fixed |
| 6 | Serialize SMB RAP share comments as bytes | High: share enumeration and share-info requests crashed by concatenating configuration strings with binary packet data; share-info offsets were also written after serialization | Unit tests cover both RAP operations and verify the encoded comment offsets and payloads | Fixed |
| 7 | Correct three-byte ASN.1 length decoding in SPNEGO | High: payloads from 65,536 through 16,777,215 bytes were sliced using an incorrectly grouped bit shift | Reproduced with a 65,536-byte encode/decode round trip; all SPNEGO tests pass after correction | Fixed |
| 8 | Return the stored NetBIOS error code | High: `NetBIOSError.get_error_code()` raised `AttributeError` instead of returning the code used by retry and error-classification callers | Direct regression coverage exercises both snake-case and compatibility accessors | Fixed |
| 9 | Return serialized NetBIOS node-status data | Medium: `NBNodeStatusResponse.rawData()` always returned `None`, violating its serialization contract | Focused test verifies the name-count, entry, and statistics byte sequence | Fixed |
| 10 | Validate TDS row value shapes before parsing | Medium: invalid scalar widths reached uninitialized/incorrect unpack formats, BITN changed Python type by width, and truncated SQL variants reached downstream structure parsing | Parser tests reject invalid scalar widths and truncated variants and verify BITN returns `bool` | Fixed |
| 11 | Normalize legacy SMB challenge strings before hash formatting | Medium: an existing relay path supplies a text challenge, which previously raised `AttributeError` before the formatter's fallback handling | Unit test covers the legacy text challenge and string account/domain path | Fixed |
| 12 | Validate LDAP shell arguments before indexing | Medium: malformed interactive commands raised `IndexError` or `AttributeError` instead of reporting invalid arguments | Tests cover missing GPO arguments and an invalid third computer argument | Fixed |
| 13 | Handle one-argument TLS syscall errors | Medium: the LDAP status tool indexed a nonexistent second exception argument and hid the original connection condition with `IndexError` | Test raises the one-argument `Unexpected EOF` form and verifies the intended classification | Fixed |
| 14 | Validate NTLM relay machine account and hash shapes centrally | Medium: malformed user configuration reached relay setup and failed later through tuple unpacking, indexing, or hex decoding | Tests cover account structure, missing separators, invalid hexadecimal values, and valid empty-LM hashes | Fixed |
| 15 | Raise parse errors for malformed UUID strings and tuples | Medium: malformed UUID inputs returned `None` or raised unrelated `AttributeError`, causing later unpacking, slicing, or byte-concatenation failures | Negative string/tuple tests, default-version coverage, and existing NDR tests verify the contracts | Fixed |
| 16 | Stop the TCP regression test from swallowing type failures | Test reliability: the test supplied text instead of bytes and ignored every unexpected exception, so it could pass without exercising the parser | The frame is now bytes and unexpected thread exceptions are propagated to the test | Fixed |
| 17 | Build registry boot keys as bytes | Medium: the example concatenated decoded binary fragments into strings and then attempted to append integer byte indexes to another string | Deterministic registry fragments verify the documented byte permutation and resulting key | Fixed |
| 18 | Compare remote-shell echo-buffer length rather than its value | Low/medium: two examples compared text/bytes directly with an integer, raising `TypeError` inside broad exception handlers and disabling stale-buffer cleanup | Both corrected scripts compile successfully | Fixed |
| 19 | Avoid subtracting a missing SMB server time | Low/medium: the NTLM information tool represented missing timestamps as integer zero and could subtract that value from a `datetime` when only boot time was present | Test covers a missing current time with a present boot time and verifies uptime is omitted | Fixed |
| 20 | Normalize SMTP EHLO responses before capability checks | Medium: Python's SMTP client exposes EHLO text as bytes, so checking for a string capability raised `TypeError`; a missing response also failed membership checks | Tests cover binary capability responses and absent EHLO data | Fixed |
| 21 | Preserve the base DCE/RPC context identifier | Medium: base initialization set the context to zero and then overwrote it with `None`, making inherited arithmetic and packet fields unsafe | Unit test verifies a newly constructed base RPC object retains context zero | Fixed |
| 22 | Normalize Kerberos principal types and compare complete component lists | High: enum/int type mixtures and prefix-only component comparison could make equivalent principals unequal or different principals equal, affecting cache and identity operations | Tests cover enum/int equality and unequal component counts | Fixed |
| 23 | Recognize Kerberos IPv6 addresses and safely stringify unknown addresses | Medium: duplicate IPv4 branches made IPv6 unreachable, while unknown address formatting referenced a nonexistent attribute | Tests verify IPv6 family/packing and unknown address formatting | Fixed |
| 24 | Write packet bytes to binary PCAP files | High: `PcapFile.write()` passed `str(pkt)` to a binary file, raising `TypeError` and failing to record packets | Test compares the complete stored capture with the serialized header and packet bytes | Fixed |
| 25 | Format unknown ICMPv6 types and codes safely | Medium: logging or printing an unrecognized wire value raised `KeyError`, obscuring the packet that needed diagnosis | Tests cover an unknown message type and an unknown code for a known type | Fixed |
| 26 | Initialize extended DCOM OBJREF signatures and element count correctly | High: constructor copy/paste assigned the first signature twice and put the signature constant in the element-count field | Test verifies both signatures and the required single-element count | Fixed |
| 27 | Correct the DCOM `SpecialPropertiesData` reserved-field layout | High: duplicate field names and an oversized raw reservation changed the NDR wire layout and discarded one field during marshalling | Round-trip test preserves the DWORD, ULONGLONG, and five reserved DWORD values independently | Fixed |
| 28 | Preserve explicit endpoint-mapper error codes without a packet | Medium: constructing `DCERPCSessionError(error_code=...)` dereferenced `None` instead of retaining the supplied code | Local test verifies construction and formatting without a response packet | Fixed |
| 29 | Do not continue key-list enumeration with a failed SMB session | High: a Kerberos login exception was swallowed when a cache variable existed, leaving an invalid connection to fail later in SAMR/registry operations | Test verifies the original login error is raised and connection state is cleared | Fixed |
| 30 | Remove duplicate protocol structure field names | High: duplicate names overwrote independent SMB, DPAPI, print-client, DHCP, replication-metadata, SOCKS, and account-record fields; several definitions also changed documented wire layouts | Structural tests cover the affected classes, and an AST inventory confirms no duplicate structure fields remain | Fixed |
| 31 | Keep LAPS v2 decryption failures on a single nullable return contract | High: unpack/connect/bind failures either continued with unbound locals or returned a boolean that callers sliced as decrypted bytes | Test verifies malformed encrypted data returns `None`; caller now stops processing that encrypted attribute | Fixed |
| 32 | Initialize remote-download filenames before cleanup | Medium: DCOM and WMI shell error handlers referenced `filename` even when path calculation failed before assignment, hiding the original error with `UnboundLocalError` | Tests force pre-assignment path failures in both shells and verify cleanup remains safe | Fixed |
| 33 | Re-raise failed LDAP/LDAPS connection setup in `GetNPUsers` | High: a repeated `strongerAuthRequired` error fell through with no assigned LDAP connection and failed later with `UnboundLocalError` | Test forces the failed helper path and verifies the original LDAP exception propagates | Fixed |
| 34 | Reject missing SMB3 negotiation responses explicitly | Medium: the NTLM information tool could return an unassigned response variable when negotiation produced no valid answer | Test drives an invalid response and verifies a clear negotiation error | Fixed |
| 35 | Separate binary serialization from `__str__` | Medium: several NDR, SPNEGO, NTLM, ccache, and keytab objects returned bytes or integers from `__str__`, which always raises `TypeError` on Python 3 | Objects now expose bytes through `__bytes__` and hexadecimal text through `__str__`; representative and existing protocol tests pass | Fixed |
| 36 | Stop BadSuccessor analysis when LDAP omits the domain SID | Medium: unsuccessful/empty SID lookup left `domain_sid` unassigned and later permission filtering could raise `UnboundLocalError` | Test verifies a missing domain SID returns a controlled failure before OU processing | Fixed |
| 37 | Return valid Kerberoast text or `None` from ticket description | High: the AES128 branch interpolated a bound `.decode` method instead of decoded hexadecimal text, while unsupported encryption returned an unassigned variable | Tests verify AES128 output content and the nullable unsupported-type contract | Fixed |
| 38 | Handle empty asynchronous accept results | Medium: `asyncore.accept()` may return `None`, which the Kerberos interception server immediately unpacked as a connection tuple | Test verifies an empty accept result is ignored | Fixed |
| 39 | Stop GoldenPac before using results from an empty controller loop | Medium: an empty domain-controller result left exception and ticket variables unassigned for code after the loop | Test verifies exploitation exits cleanly when discovery returns no controllers | Fixed |
| 40 | Guard netview cleanup before executor construction succeeds | Low/medium: constructor failures and early interrupts reached `executer.stop()` before `executer` existed, replacing the original error with `UnboundLocalError` | Corrected script compiles successfully | Fixed |
| 41 | Validate SCCM policy XML elements before dereferencing | Medium: server-controlled policies could omit text/value children or contain non-hex blobs, causing `None` dereferences and conversion failures | Tests cover missing secret children and missing CollectionSettings values | Fixed |
| 42 | Preserve SACL state when an LDAP security descriptor has no DACL | High: the absent-DACL branch cleared `Sacl` instead of `Dacl`, corrupting the parsed descriptor state | Round-trip test uses a present SACL and absent DACL | Fixed |
| 43 | Correct LDAP ACE padding type and alignment | High: padding concatenated text to bytes and rounded sizes using the remainder rather than the distance to the next four-byte boundary | Tests verify byte padding and a 5-byte ACE rounds to 8 bytes | Fixed |
| 44 | Accept omitted LDAP add attributes | Medium: `LDAPConnection.add()` documented `attributes=None` but immediately called `.items()` on it | Mocked add request verifies the default builds and succeeds | Fixed |
| 45 | Validate relay-attack identity, IMAP, WinRM, SCCM policy, and distribution-point data shapes | High: relay inputs assumed domain separators, nonempty IMAP results, text email payloads, mandatory WinRM regex matches, valid multipart sections, nested dictionaries, and UTF-8 responses | Nine focused tests cover domainless users, binary mail, required WinRM fields, malformed/missing policy data, scalar recursion nodes, and blank target lines | Fixed |
| 46 | Convert invalid `rpcmap -uuid` values into CLI argument errors | Medium: stricter UUID parsing initially exposed an uncaught caller traceback | Subprocess test verifies exit status 2, a useful parser message, and no traceback | Fixed |

## Reviewed areas

| Area | Status | Notes |
|---|---|---|
| Foundational structures and packet classes | Complete | NetBIOS, UUID, PCAP, ICMPv6, DPAPI, ESE, packet, and structure modules reviewed |
| TDS and MSSQL | Complete | Scalar widths, result typing, variants, metadata, and reply paths reviewed |
| SMB and SMB server/client code | Complete | SMB1/2/3 client/server state, string handling, path checks, RAP, and tests reviewed |
| DCE/RPC and generated protocol structures | Complete | NDR/runtime state plus DCOM, print, DHCP, replication, EPM, and WMI structures reviewed |
| Kerberos and authentication | Complete | SPNEGO/NTLM, Kerberos crypto/types, ccache, keytab, and LDAP authentication boundaries reviewed |
| LDAP and remaining protocol modules | Complete | Core LDAP package and all 13 NTLM relay attack plugin files received targeted file-by-file passes |
| Bundled examples and command-line tools | Complete | All example/tool files received checker-driven and file-by-file passes; confirmed defects were corrected |
| Tests, setup, and support scripts | Complete | Test masking, packaging/configuration, structure declarations, and local test coverage reviewed |

## Checker disagreements and rejected findings

Record false positives and checker disagreements here so they are not
re-investigated without new evidence.

| Location | Finding | Resolution |
|---|---|---|
| Broad dynamic-attribute diagnostics | ty, Pyright, and mypy infer many packet fields as missing because Impacket creates them dynamically | Treat as non-actionable unless a concrete runtime path demonstrates an invalid field or state |
| `dpapi.py` algorithm table indexes | Checkers infer all algorithm tuples have the same shape and flag valid hash-only index 4 access | Hash entries have five fields while cipher entries have four; runtime keys constrain each access correctly |
| NDR and `Structure` fields | Checkers infer heterogeneous field dictionaries as wide unions and report subscripting/operator failures | Field descriptors and discriminators constrain the runtime value; only findings with a failing concrete path were changed |
| State initialized to `None` then assigned before use | Checkers report Optional access across connection and protocol classes | Rejected where every reachable path assigns or exits; fixed where exceptions or empty loops could bypass assignment |
| Regex and ASN.1 Optional values | Checkers often retain `None` after guards they cannot model | Rejected when the exact guard dominates the access; fixed missing guards in WinRM, SCCM, UUID, and LDAP-facing code |
| Legacy binary `__str__` methods | Some code historically used `__str__` as serialization | On supported Python 3 this raised `TypeError`; binary output now uses `__bytes__`, while `__str__` returns hexadecimal text |

## Validation log

Targeted tests and existing repository checks will be recorded alongside each
accepted change.

| Change | Validation | Result |
|---|---|---|
| Audit setup | Branch and repository status | Passed |
| SPNEGO three-byte ASN.1 length | `python -m pytest -q tests/SMB_RPC/test_spnego.py` | 7 passed |
| NetBIOS error code and node-status serialization | `python -m pytest -q tests/SMB_RPC/test_nmb.py -m "not remote"` | 7 passed, 6 remote tests deselected |
| DCOM request, object-reference, reserved-field, and WMI structures | `python -m pytest -q tests/dcerpc/test_dcomrt.py::DCOMLocalTests` | 4 passed |
| SMB path information, string decoding, hash formatting, and RAP comments | `python -m pytest -q tests/SMB_RPC/test_smbserver.py::SMBServerUnitTests` | 8 passed |
| LDAP shell argument handling | `python -m pytest -q tests/misc/test_ldap_shell.py` | 2 passed |
| LDAP status syscall error handling | `python -m pytest -q tests/misc/test_check_ldap_status.py` | 1 passed |
| NTLM relay machine account configuration | `python -m pytest -q tests/misc/test_ntlmrelayx_config.py` | 4 passed |
| UUID parsing and tuple conversion | `python -m pytest -q tests/misc/test_uuid.py tests/SMB_RPC/test_ndr.py` | 21 passed |
| TDS row value validation | `python -m pytest -q tests/misc/test_tds.py` | 22 passed, 5 subtests passed |
| TCP option parser regression test | `python -m pytest -q tests/ImpactPacket/test_TCP_bug_issue7.py` | 1 passed |
| Registry boot-key byte handling | `python -m pytest -q tests/misc/test_registry_read.py` | 1 passed |
| Remote-shell stale-buffer checks | `python -m py_compile examples/goldenPac.py examples/raiseChild.py` | Passed |
| NTLM information timestamp and negotiation handling | `python -m pytest -q tests/misc/test_dump_ntlm_info.py` | 2 passed |
| DCOM example OBJREF handling | `python -m pytest -q tests/misc/test_dcomexec.py` | 2 passed |
| SMTP relay EHLO handling | `python -m pytest -q tests/misc/test_smtp_relay_client.py` | 2 passed |
| DCE/RPC base context initialization | `python -m pytest -q tests/misc/test_rpcrt.py` | 1 passed |
| Kerberos principal and address behavior | `python -m pytest -q tests/misc/test_krb5_types.py` | 4 passed |
| PCAP binary serialization | `python -m pytest -q tests/misc/test_pcapfile.py` | 1 passed |
| ICMPv6 unknown value formatting | `python -m pytest -q tests/misc/test_icmp6.py` | 2 passed |
| Endpoint-mapper session errors | `python -m pytest -q tests/dcerpc/test_epm.py::EPMLocalTests` | 1 passed |
| Key-list SMB connection failure | `python -m pytest -q tests/misc/test_keylistattack.py` | 1 passed |
| Protocol structure field uniqueness | `python -m pytest -q tests/misc/test_protocol_structure_fields.py`; AST inventory | 7 passed, 7 subtests passed; zero duplicate fields |
| LAPS v2 encrypted blob failure | `python -m pytest -q tests/misc/test_get_laps_password.py` | 1 passed |
| DCOM and WMI remote-download cleanup | `python -m pytest -q tests/misc/test_remote_shell_downloads.py` | 2 passed |
| GetNPUsers LDAP setup failure | `python -m pytest -q tests/misc/test_get_np_users.py` | 1 passed |
| Binary protocol string/bytes contracts | `python -m pytest -q tests/misc/test_binary_string_methods.py tests/SMB_RPC/test_spnego.py tests/SMB_RPC/test_ntlm.py` | 15 passed, 3 subtests passed |
| BadSuccessor missing domain SID | `python -m pytest -q tests/misc/test_badsuccessor.py` | 1 passed |
| Kerberoast ticket hash formatting | `python -m pytest -q tests/misc/test_describe_ticket.py` | 2 passed |
| Kerberos interception empty accept | `python -m pytest -q tests/misc/test_kintercept.py` | 1 passed |
| GoldenPac empty domain-controller discovery | `python -m pytest -q tests/misc/test_golden_pac.py` | 1 passed |
| Netview executor cleanup | `python -m py_compile examples/netview.py` | Passed |
| SCCM policy XML shape handling | `python -m pytest -q tests/misc/test_sccm_policies_attack.py` | 4 passed |
| LDAP descriptor, ACE, and add-request behavior | `python -m pytest -q tests/misc/test_ldap_core.py` | 4 passed |
| Relay attack external data shapes | `python -m pytest -q tests/misc/test_relay_attacks.py tests/misc/test_sccm_policies_attack.py` | 9 passed |
| rpcmap invalid UUID handling | `python -m pytest -q tests/misc/test_rpcmap.py tests/misc/test_uuid.py` | 5 passed |
| Consolidated local regression suite | `python -m pytest -q tests/misc` | 184 passed, 1 skipped |
| Consolidated SMB, NDR, DCOM, and EPM regressions | Targeted `tests/SMB_RPC` and `tests/dcerpc` selectors | 47 passed, 6 remote tests deselected |
| Full existing local test suite | `python -m pytest -q -m "not remote"` | 641 passed, 4 skipped, 25 subtests passed |
| New test lint, source compilation, and whitespace | Ruff on new tests; `compileall`; CRLF-aware `git diff --check` | Passed |
