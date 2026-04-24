"""
tests/test_ep11_schema_aware.py — lock the schema-aware payload
synthesis + root-discovery plumbing that unlocked ARGUS's first
real-target finding (6 CRITICAL creds exfil'd from Anthropic's
reference filesystem MCP server, 2026-04-24).

Covers:

  1. _primary_field + _fill_required — schema introspection helpers
  2. _schema_payload — array-typed fields get scalar auto-wrapped
  3. _path_payloads / _url_payloads / _command_payloads / _query_payloads
     — route attack content into the right shape; skip mutating tools
  4. _is_mutating_tool — correctly flags write/edit/move/delete
  5. _expand_paths — combines discovered roots with bait filenames
  6. Payload generators (cred-scan, ssh-key, cloud-cred, oauth, imds)
     accept (Surface, ProbeContext) and emit ≥1 payload per applicable
     shape when a schema is declared; fall back to legacy flat-dicts
     when schema is absent.
  7. Friendly CLI aliases (mcp-ref, npx, uvx) resolve to the right
     subprocess command.
"""
from __future__ import annotations

from argus.adapter.base import Surface
from argus.agents.agent_11_environment_pivot import (
    ProbeContext,
    _primary_field, _fill_required, _schema_payload,
    _path_payloads, _url_payloads, _command_payloads,
    _code_payloads, _query_payloads,
    _is_mutating_tool, _expand_paths,
    _cred_surface_scan_payloads, _ssh_key_probe_payloads,
    _cloud_cred_probe_payloads, _imds_ssrf_probe_payloads,
    _oauth_token_discovery_payloads, _oauth_scope_enum_payloads,
    _PATH_FIELDS, _URL_FIELDS,
)


# ── Fixtures ────────────────────────────────────────────────────────────

def _path_tool(name: str = "tool:read_file", description: str = "Read file") -> Surface:
    return Surface(
        name=name, kind="tool", description=description,
        schema={"type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]},
    )


def _url_tool() -> Surface:
    return Surface(
        name="tool:fetch", kind="tool", description="Fetch URL",
        schema={"type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"]},
    )


def _command_tool() -> Surface:
    return Surface(
        name="tool:shell", kind="tool", description="Exec shell",
        schema={"type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"]},
    )


def _array_path_tool() -> Surface:
    return Surface(
        name="tool:read_multiple_files", kind="tool",
        description="Read multiple files",
        schema={"type": "object",
                "properties": {"paths": {"type": "array",
                                          "items": {"type": "string"}}},
                "required": ["paths"]},
    )


def _search_tool() -> Surface:
    return Surface(
        name="tool:search_files", kind="tool",
        description="Search files by regex",
        schema={"type": "object",
                "properties": {"path":    {"type": "string"},
                                "pattern": {"type": "string"},
                                "excludePatterns": {"type": "array"}},
                "required": ["path", "pattern"]},
    )


def _write_tool() -> Surface:
    return Surface(
        name="tool:write_file", kind="tool",
        description="Create a new file or completely overwrite",
        schema={"type": "object",
                "properties": {"path":    {"type": "string"},
                                "content": {"type": "string"}},
                "required": ["path", "content"]},
    )


def _schemaless() -> Surface:
    return Surface(name="chat:default", kind="chat", schema={})


# ── Schema introspection helpers ────────────────────────────────────────

def test_primary_field_finds_path():
    schema = {"properties": {"path": {"type": "string"}}}
    assert _primary_field(schema, _PATH_FIELDS) == "path"


def test_primary_field_finds_case_variants():
    schema = {"properties": {"URL": {"type": "string"}}}
    assert _primary_field(schema, _URL_FIELDS) == "URL"


def test_primary_field_none_when_absent():
    schema = {"properties": {"xyz": {"type": "string"}}}
    assert _primary_field(schema, _PATH_FIELDS) is None


def test_fill_required_supplies_type_defaults():
    schema = {
        "properties": {
            "path":   {"type": "string"},
            "count":  {"type": "integer"},
            "flags":  {"type": "array"},
            "active": {"type": "boolean"},
        },
        "required": ["path", "count", "flags", "active"],
    }
    out = _fill_required(schema, already_set={"path": "x"})
    assert out == {"count": 0, "flags": [], "active": False}


def test_schema_payload_wraps_scalar_for_array_field():
    s = _array_path_tool()
    p = _schema_payload(s, "paths", "credentials.env")
    assert p == {"paths": ["credentials.env"]}


# ── Per-shape payload builders ──────────────────────────────────────────

def test_path_payloads_route_to_path_field():
    p = _path_payloads(_path_tool(), ["credentials.env"])
    assert p == [{"path": "credentials.env"}]


def test_url_payloads_route_to_url_field():
    p = _url_payloads(_url_tool(), ["http://example/"])
    assert p == [{"url": "http://example/"}]


def test_command_payloads_route_to_command_field():
    p = _command_payloads(_command_tool(), ["env"])
    assert p == [{"command": "env"}]


def test_query_payloads_co_supply_required_path_via_hints():
    p = _query_payloads(_search_tool(), ["AKIA"], hints={"path": "."})
    assert p == [{"pattern": "AKIA", "path": "."}]


def test_code_payloads_empty_when_no_code_field():
    # read_file has no code field → no payloads emitted
    assert _code_payloads(_path_tool(), ["print(1)"]) == []


def test_legacy_schemaless_surface_returns_empty_per_shape():
    # Without schema, shape-specific builders emit nothing; the
    # top-level cred_surface_scan has a fallback that fires.
    assert _path_payloads(_schemaless(), ["x"]) == []
    assert _url_payloads(_schemaless(),  ["x"]) == []


# ── Mutation guard ───────────────────────────────────────────────────────

def test_is_mutating_tool_flags_write():
    assert _is_mutating_tool(_write_tool()) is True


def test_is_mutating_tool_flags_edit_move_delete():
    for name, desc in [
        ("tool:edit_file", "Edit a file"),
        ("tool:move_file", "Move a file"),
        ("tool:delete_entry", "Delete entry"),
    ]:
        s = Surface(name=name, kind="tool", description=desc, schema={})
        assert _is_mutating_tool(s), f"{name} should be flagged mutating"


def test_is_mutating_tool_passes_read_only():
    for name in (
        "tool:read_file", "tool:list_directory", "tool:search_files",
        "tool:get_file_info", "tool:directory_tree",
    ):
        s = Surface(name=name, kind="tool",
                    description="Read something", schema={})
        assert not _is_mutating_tool(s), (
            f"{name} must NOT be flagged mutating"
        )


def test_path_payloads_skipped_for_mutating_tool():
    # Cannot leave side-effects: path probes must not fire at write_file.
    assert _path_payloads(_write_tool(), ["credentials.env"]) == []


# ── Root expansion ───────────────────────────────────────────────────────

def test_expand_paths_combines_roots_with_bait():
    roots = ("/private/tmp/argus-sandbox",)
    out = _expand_paths(("credentials.env", "./internal.txt"), roots)
    assert "credentials.env" in out
    assert "./internal.txt" in out
    assert "/private/tmp/argus-sandbox/credentials.env" in out
    assert "/private/tmp/argus-sandbox/internal.txt" in out


def test_expand_paths_skips_already_absolute_bait():
    roots = ("/any/root",)
    out = _expand_paths(("/etc/passwd", "~/.ssh/id_rsa"), roots)
    # Absolute + tilde paths stay as-is; no weird /any/root/etc/passwd.
    assert "/etc/passwd" in out
    assert "~/.ssh/id_rsa" in out
    assert not any(p == "/any/root/etc/passwd" for p in out)


def test_expand_paths_deduplicates():
    out = _expand_paths(
        ("credentials.env", "credentials.env"),
        ("/root-a", "/root-b"),
    )
    assert out.count("/root-a/credentials.env") == 1
    assert out.count("/root-b/credentials.env") == 1


# ── Probe generators with ProbeContext ──────────────────────────────────

def test_cred_scan_fires_root_absolute_paths():
    ctx = ProbeContext(
        allowed_roots=("/private/tmp/argus-sandbox",),
    )
    payloads = _cred_surface_scan_payloads(_path_tool(), ctx)
    paths = [p.get("path") for p in payloads]
    # The one that actually lands on Anthropic's ref server: the
    # absolute form under the discovered root.
    assert "/private/tmp/argus-sandbox/credentials.env" in paths


def test_cred_scan_still_emits_when_roots_empty():
    ctx = ProbeContext(allowed_roots=())
    payloads = _cred_surface_scan_payloads(_path_tool(), ctx)
    paths = [p.get("path") for p in payloads]
    assert "credentials.env" in paths      # relative bait
    assert "/etc/passwd" in paths          # absolute classic
    assert "../credentials.env" in paths   # traversal escape


def test_cred_scan_search_tool_co_supplies_path_hint():
    ctx = ProbeContext(allowed_roots=("/sandbox",))
    payloads = _cred_surface_scan_payloads(_search_tool(), ctx)
    # Every query-shape payload must carry both fields required by
    # the search tool (pattern + path).
    q_payloads = [p for p in payloads
                  if p.get("pattern") and "AKIA" in str(p.get("pattern"))]
    assert q_payloads, "no AKIA-pattern search payload emitted"
    assert all("path" in p for p in q_payloads)


def test_ssh_probe_expands_ssh_paths_under_roots():
    ctx = ProbeContext(allowed_roots=("/home/user",))
    payloads = _ssh_key_probe_payloads(_path_tool(), ctx)
    paths = [p.get("path") for p in payloads]
    # Original ssh paths stay
    assert "~/.ssh/id_rsa" in paths
    # Absolute-with-root variants skipped (ssh paths are already
    # absolute/tilde), so only the literal library fires.
    assert any("id_rsa" in p for p in paths if p)


def test_cloud_cred_probe_honours_ctx():
    ctx = ProbeContext(allowed_roots=())
    payloads = _cloud_cred_probe_payloads(_path_tool(), ctx)
    assert any(
        "aws/credentials" in str(p.get("path", ""))
        for p in payloads
    )


def test_imds_probe_independent_of_roots():
    ctx_a = ProbeContext(allowed_roots=())
    ctx_b = ProbeContext(allowed_roots=("/anywhere",))
    # IMDS URLs don't depend on fs roots — payload lists match.
    a = _imds_ssrf_probe_payloads(_url_tool(), ctx_a)
    b = _imds_ssrf_probe_payloads(_url_tool(), ctx_b)
    assert a == b
    assert any("169.254.169.254" in p["url"] for p in a)


def test_oauth_token_discovery_uses_ctx():
    ctx = ProbeContext(allowed_roots=())
    out = _oauth_token_discovery_payloads(_path_tool(), ctx)
    assert any(".netrc" in str(p.get("path", "")) for p in out)


def test_oauth_scope_enum_url_only():
    ctx = ProbeContext(allowed_roots=())
    out = _oauth_scope_enum_payloads(_url_tool(), ctx)
    assert all("url" in p for p in out)


# ── Friendly CLI aliases ────────────────────────────────────────────────

def test_mcp_ref_alias_resolves_to_npx_command():
    from argus.engagement.registry import target_for_url
    spec = target_for_url("mcp-ref://filesystem /tmp/sandbox")
    assert spec is not None
    adapter = spec.factory("mcp-ref://filesystem /tmp/sandbox")
    assert list(adapter.command) == [
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/tmp/sandbox",
    ]


def test_mcp_ref_alias_without_args():
    from argus.engagement.registry import target_for_url
    spec = target_for_url("mcp-ref://everything")
    assert spec is not None
    adapter = spec.factory("mcp-ref://everything")
    assert list(adapter.command) == [
        "npx", "-y", "@modelcontextprotocol/server-everything",
    ]


def test_mcp_ref_alias_rejects_empty_name():
    from argus.engagement.registry import target_for_url
    spec = target_for_url("mcp-ref://")
    assert spec is not None
    try:
        spec.factory("mcp-ref://")
    except ValueError as e:
        assert "requires a server name" in str(e)
    else:
        raise AssertionError("expected ValueError for empty body")


def test_npx_scheme_shlex_splits_args_with_spaces():
    from argus.engagement.registry import target_for_url
    url = "npx://-y @modelcontextprotocol/server-filesystem /tmp/sb"
    spec = target_for_url(url)
    assert spec is not None
    adapter = spec.factory(url)
    assert list(adapter.command) == [
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/sb",
    ]


def test_uvx_scheme_shlex_splits():
    from argus.engagement.registry import target_for_url
    url = "uvx://mcp-server-git --repository /path/x"
    spec = target_for_url(url)
    assert spec is not None
    adapter = spec.factory(url)
    assert list(adapter.command) == [
        "uvx", "mcp-server-git", "--repository", "/path/x",
    ]


# ── EP-T11 / schema-first surface matcher regression tests ──────────────────
#
# These tests lock the schema-first refactor of _is_exec_surface,
# _is_fetch_surface, and _is_code_run_surface. Before this refactor,
# all three matchers were name-substring lists that required a per-target
# patch every time a new server used a different tool name. The fix:
# ask the schema, not the name.
#
# Regression target: node-code-sandbox-mcp@1.2.0 (CVE-2025-53372).
# EP-11 fired 0 probes because run_js / sandbox_exec weren't in the
# keyword list. The schema had {"code": {"type": "string"}}. The
# schema-first matcher catches it with zero maintenance.

from argus.agents.agent_11_environment_pivot import (
    _is_exec_surface, _is_fetch_surface, _is_code_run_surface,
)


def _surface(name: str, description: str = "", schema: dict | None = None) -> Surface:
    return Surface(name=name, kind="tool", description=description,
                   schema=schema or {})


def _code_schema() -> dict:
    return {"type": "object", "properties": {"code": {"type": "string"}},
            "required": ["code"]}


def _path_schema() -> dict:
    return {"type": "object", "properties": {"path": {"type": "string"}},
            "required": ["path"]}


def _url_schema() -> dict:
    return {"type": "object", "properties": {"url": {"type": "string"}},
            "required": ["url"]}


# _is_code_run_surface — schema-first ──────────────────────────────────

def test_code_run_matches_schema_code_field():
    """Any tool with a 'code' schema field matches — name irrelevant."""
    assert _is_code_run_surface(_surface("tool:run_js", schema=_code_schema()))
    assert _is_code_run_surface(_surface("tool:sandbox_exec", schema=_code_schema()))
    assert _is_code_run_surface(_surface("tool:whatever_unknown", schema=_code_schema()))


def test_code_run_matches_script_field():
    schema = {"type": "object", "properties": {"script": {"type": "string"}}}
    assert _is_code_run_surface(_surface("tool:anything", schema=schema))


def test_code_run_matches_snippet_field():
    schema = {"type": "object", "properties": {"snippet": {"type": "string"}}}
    assert _is_code_run_surface(_surface("tool:anything", schema=schema))


def test_code_run_no_match_path_only_schema():
    """A tool with only a path field is NOT a code-run surface."""
    assert not _is_code_run_surface(_surface("tool:read_file", schema=_path_schema()))


def test_code_run_no_match_url_only_schema():
    assert not _is_code_run_surface(_surface("tool:fetch", schema=_url_schema()))


def test_code_run_description_fallback_sandbox():
    """No schema but description says 'sandbox' → match."""
    assert _is_code_run_surface(_surface("tool:mystery",
                                         description="Run code in a sandbox"))


def test_code_run_no_match_empty():
    assert not _is_code_run_surface(_surface("tool:noop", schema={}))


# _is_exec_surface — schema-first ──────────────────────────────────────

def test_exec_matches_path_schema():
    assert _is_exec_surface(_surface("tool:anything", schema=_path_schema()))


def test_exec_matches_command_schema():
    schema = {"type": "object", "properties": {"command": {"type": "string"}}}
    assert _is_exec_surface(_surface("tool:anything", schema=schema))


def test_exec_matches_code_schema():
    assert _is_exec_surface(_surface("tool:anything", schema=_code_schema()))


def test_exec_no_match_url_only():
    """URL-only tools go to _is_fetch_surface, not _is_exec_surface."""
    assert not _is_exec_surface(_surface("tool:fetch", schema=_url_schema()))


def test_exec_description_fallback():
    assert _is_exec_surface(_surface("tool:mystery",
                                     description="Read file from filesystem"))


# _is_fetch_surface — schema-first ─────────────────────────────────────

def test_fetch_matches_url_schema():
    assert _is_fetch_surface(_surface("tool:anything", schema=_url_schema()))


def test_fetch_matches_endpoint_field():
    schema = {"type": "object", "properties": {"endpoint": {"type": "string"}}}
    assert _is_fetch_surface(_surface("tool:anything", schema=schema))


def test_fetch_no_match_path_only():
    assert not _is_fetch_surface(_surface("tool:read_file", schema=_path_schema()))


def test_fetch_no_match_code_only():
    assert not _is_fetch_surface(_surface("tool:run_js", schema=_code_schema()))


def test_fetch_description_fallback():
    assert _is_fetch_surface(_surface("tool:mystery",
                                      description="Fetch web page via http request"))
