// Consolidated multi-action tool multiplexors (RFC-001).
// Thin action-routing layer over the existing atomic handlers: each new
// tool name (log_stream, service_manage, process_manage, browser_manage)
// dispatches to the granular handler that already implements the work.
// No functionality is reimplemented here; unknown actions fail closed
// with an INVALID_ARGUMENT envelope.
function payloadOf(job) {
  const r = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  return /** @type {Record<string, unknown>} */ (r.request_payload || r.payload || {});
}

/**
 * @param {unknown} job
 * @param {Record<string, unknown>} mapped
 */
function subJob(job, mapped) {
  const base = payloadOf(job);
  const merged = { ...base, ...mapped };
  return { ...(job && typeof job === 'object' ? job : {}), request_payload: merged, payload: merged };
}

const fail = (/** @type {unknown} */ error) => ({
  status: 'failed',
  exit_code: null,
  stdout: '',
  stderr: '',
  error: String(error),
  duration_ms: 0,
  result_payload: {}
});

/**
 * @param {Record<string, unknown>} atomic granular handler registry
 * @param {string} name
 */
function requireHandler(atomic, name) {
  const h = atomic[name];
  return typeof h === 'function'
    ? /** @type {(job: unknown) => Promise<Record<string, unknown>>} */ (h)
    : null;
}

/**
 * @param {unknown} v
 */
function asStringOrUndefined(v) {
  return typeof v === 'string' ? v : undefined;
}

/**
 * log_stream(action=start|stop|read) over log_follow_start/stop/read.
 * Accepts both the consolidated names (handle, cursor, limit, max_lines)
 * and the granular names (max_bytes, max_lines) so hub- and direct-shaped
 * payloads both route.
 * @param {unknown} job
 * @param {Record<string, unknown>} atomic
 */
async function logStream(job, atomic) {
  const p = payloadOf(job);
  const action = String(p.action || '').toLowerCase();
  if (action === 'start') {
    const h = requireHandler(atomic, 'log_follow_start');
    if (!h) return fail('UNSUPPORTED_TOOL:log_stream');
    return h(
      subJob(job, {
        // Omit an absent handle so the atomic log_follow_start mints one
        // per contract ("returned by action=start"); forward a supplied
        // handle verbatim so the atomic INVALID_HANDLE gate still applies.
        ...(p.handle !== undefined && p.handle !== null && String(p.handle) !== ''
          ? { handle: p.handle }
          : {}),
        source: p.source,
        ...(asStringOrUndefined(p.path) !== undefined ? { path: p.path } : {}),
        max_lines: p.max_lines ?? p.limit ?? 200
      })
    );
  }
  if (action === 'stop') {
    const h = requireHandler(atomic, 'log_follow_stop');
    if (!h) return fail('UNSUPPORTED_TOOL:log_stream');
    return h(subJob(job, { handle: p.handle }));
  }
  if (action === 'read') {
    const h = requireHandler(atomic, 'log_follow_read');
    if (!h) return fail('UNSUPPORTED_TOOL:log_stream');
    return h(
      subJob(job, {
        handle: p.handle,
        cursor: p.cursor ?? p.offset ?? 0,
        max_bytes: p.max_bytes ?? p.length ?? 65536,
        ...(p.limit !== undefined ? { limit: p.limit } : {})
      })
    );
  }
  return fail(`INVALID_ARGUMENT: unknown log_stream action '${String(p.action || '')}'`);
}

/**
 * service_manage(action=status|start|stop|restart|enable|disable) over
 * service_status / service_list / service_start / service_stop /
 * service_restart / service_enable / service_disable. `list` is accepted
 * as an alias of inventory status. Name fields accept both `service`
 * (consolidated) and `unit` (granular).
 * @param {unknown} job
 * @param {Record<string, unknown>} atomic
 */
async function serviceManage(job, atomic) {
  const p = payloadOf(job);
  const action = String(p.action || '').toLowerCase();
  const service = String(p.service ?? p.unit ?? p.name ?? '');
  if (action === 'status') {
    if (service) {
      const h = requireHandler(atomic, 'service_status');
      if (!h) return fail('UNSUPPORTED_TOOL:service_manage');
      return h(subJob(job, { unit: service, service }));
    }
    const h = requireHandler(atomic, 'service_list');
    if (!h) return fail('UNSUPPORTED_TOOL:service_manage');
    return h(subJob(job, { limit: p.limit ?? 200 }));
  }
  if (action === 'list') {
    const h = requireHandler(atomic, 'service_list');
    if (!h) return fail('UNSUPPORTED_TOOL:service_manage');
    return h(subJob(job, { limit: p.limit ?? 200 }));
  }
  if (
    action === 'start' ||
    action === 'stop' ||
    action === 'restart' ||
    action === 'enable' ||
    action === 'disable'
  ) {
    const h = requireHandler(atomic, `service_${action}`);
    if (!h) return fail('UNSUPPORTED_TOOL:service_manage');
    return h(subJob(job, { service, unit: service }));
  }
  return fail(`INVALID_ARGUMENT: unknown service_manage action '${String(p.action || '')}'`);
}

/**
 * process_manage(action=list|start|stop|read|input) over process_list /
 * process_start / process_terminate / process_output / process_input.
 * `terminate` and `output` are accepted as aliases of `stop` and `read`.
 * Identifier fields accept both `process_id` (granular handle) and `pid`;
 * cursor fields accept stdout_cursor/stderr_cursor, offset, and cursor;
 * byte budgets accept max_bytes and length.
 * @param {unknown} job
 * @param {Record<string, unknown>} atomic
 */
async function processManage(job, atomic) {
  const p = payloadOf(job);
  let action = String(p.action || '').toLowerCase();
  if (action === 'terminate' || action === 'kill') action = 'stop';
  if (action === 'output') action = 'read';
  const id = String(p.process_id ?? p.pid ?? p.handle ?? '');
  if (action === 'list') {
    const h = requireHandler(atomic, 'process_list');
    if (!h) return fail('UNSUPPORTED_TOOL:process_manage');
    // F-06: served schema default is managed (managed sessions are cheap;
    // system enumerates OS processes). The old 'system' default returned
    // the ~48KB OS table for every scope-less call.
    return h(subJob(job, { scope: p.scope ?? 'managed', limit: p.limit }));
  }
  if (action === 'start') {
    const h = requireHandler(atomic, 'process_start');
    if (!h) return fail('UNSUPPORTED_TOOL:process_manage');
    const mapped = /** @type {Record<string, unknown>} */ ({});
    if (Array.isArray(p.command)) {
      const argv = p.command.map(String);
      if (argv.length > 0 && p.executable === undefined && p.args === undefined) {
        mapped.executable = argv[0];
        mapped.args = argv.slice(1);
      }
    }
    if (p.executable !== undefined) mapped.executable = String(p.executable);
    if (p.args !== undefined) mapped.args = p.args;
    if (id) mapped.process_id = id;
    if (p.cwd !== undefined || p.working_directory !== undefined)
      mapped.cwd = p.cwd ?? p.working_directory;
    if (p.env !== undefined) mapped.env = p.env;
    if (p.timeout_seconds !== undefined) mapped.timeout_seconds = p.timeout_seconds;
    if (p.idle_timeout_seconds !== undefined)
      mapped.idle_timeout_seconds = p.idle_timeout_seconds;
    if (p.pty !== undefined) mapped.pty = p.pty;
    return h(subJob(job, mapped));
  }
  if (action === 'stop') {
    const h = requireHandler(atomic, 'process_terminate');
    if (!h) return fail('UNSUPPORTED_TOOL:process_manage');
    return h(
      subJob(job, {
        process_id: id,
        ...(p.force !== undefined ? { force: p.force } : {}),
        ...(p.grace_ms !== undefined ? { grace_ms: p.grace_ms } : {})
      })
    );
  }
  if (action === 'read') {
    const h = requireHandler(atomic, 'process_output');
    if (!h) return fail('UNSUPPORTED_TOOL:process_manage');
    return h(
      subJob(job, {
        process_id: id,
        stdout_cursor: p.stdout_cursor ?? p.offset ?? p.cursor ?? 0,
        stderr_cursor: p.stderr_cursor ?? p.offset ?? p.cursor ?? 0,
        max_bytes: p.max_bytes ?? p.length ?? p.limit ?? 65536,
        ...(p.wait_ms !== undefined ? { wait_ms: p.wait_ms } : {})
      })
    );
  }
  if (action === 'input') {
    const h = requireHandler(atomic, 'process_input');
    if (!h) return fail('UNSUPPORTED_TOOL:process_manage');
    return h(
      subJob(job, {
        process_id: id,
        data: String(p.data ?? ''),
        ...(p.wait_for_prompt !== undefined ? { wait_for_prompt: p.wait_for_prompt } : {}),
        ...(p.timeout_ms !== undefined ? { timeout_ms: p.timeout_ms } : {})
      })
    );
  }
  return fail(`INVALID_ARGUMENT: unknown process_manage action '${String(p.action || '')}'`);
}

/**
 * @param {string} raw
 */
function mapInteractAction(raw) {
  const a = String(raw || '').toLowerCase();
  if (a === 'scroll') return 'scroll_into_view';
  if (a === 'wait') return 'wait_for';
  return a || 'click';
}

/**
 * @param {string} raw
 */
function mapTabsAction(raw) {
  const a = String(raw || '').toLowerCase();
  if (a === 'open' || a === 'new') return 'new';
  if (a === 'switch' || a === 'select') return 'select';
  if (a === 'close') return 'close';
  return 'list';
}

/**
 * browser_manage over the browser_* granular handlers:
 * create->browser_create, navigate->browser_navigate,
 * interact->browser_interact, inspect->browser_snapshot (or
  * browser_take_screenshot for format=screenshot), tabs->browser_tabs
  * (11.9.0 F3: retired action=tab_manage removed — tabs is the only tab
  * path and a strict superset: list/open/close/switch all ride action=tabs
  * with action_type; tab_manage had no list and shared this handler),
  * upload->browser_file_upload, close->browser_close.
 * @param {unknown} job
 * @param {Record<string, unknown>} atomic
 */
async function browserManage(job, atomic) {
  const p = payloadOf(job);
  const action = String(p.action || '').toLowerCase();
  if (action === 'create') {
    const h = requireHandler(atomic, 'browser_create');
    if (!h) return fail('UNSUPPORTED_TOOL:browser_manage');
    return h(subJob(job, {}));
  }
  if (action === 'navigate') {
    const h = requireHandler(atomic, 'browser_navigate');
    if (!h) return fail('UNSUPPORTED_TOOL:browser_manage');
    return h(subJob(job, {}));
  }
  if (action === 'interact') {
    const h = requireHandler(atomic, 'browser_interact');
    if (!h) return fail('UNSUPPORTED_TOOL:browser_manage');
    const sub = String(p.action_type ?? p.sub_action ?? p.operation ?? 'click');
    return h(
      subJob(job, {
        action: mapInteractAction(sub),
        target: p.target ?? p.selector ?? '',
        selector: p.selector ?? p.target ?? '',
        value: p.value ?? '',
        ...(p.timeout_ms !== undefined ? { timeout_ms: p.timeout_ms } : {})
      })
    );
  }
  if (action === 'inspect') {
    const format = String(p.format ?? p.type ?? 'accessibility').toLowerCase();
    if (format === 'screenshot') {
      const h = requireHandler(atomic, 'browser_take_screenshot');
      if (!h) return fail('UNSUPPORTED_TOOL:browser_manage');
      return h(subJob(job, {}));
    }
    const h = requireHandler(atomic, 'browser_snapshot');
    if (!h) return fail('UNSUPPORTED_TOOL:browser_manage');
    return h(
      subJob(job, {
        type: format === 'html' || format === 'text' ? format : 'accessibility'
      })
    );
  }
  if (action === 'tabs') {
    const h = requireHandler(atomic, 'browser_tabs');
    if (!h) return fail('UNSUPPORTED_TOOL:browser_manage');
    const sub = String(p.action_type ?? p.sub_action ?? p.operation ?? 'list');
    const pageId = p.page_id ?? p.tab_id ?? '';
    return h(
      subJob(job, {
        action: mapTabsAction(sub),
        ...(pageId !== '' ? { page_id: pageId } : {}),
        ...(p.url !== undefined ? { url: p.url } : {})
      })
    );
  }
  if (action === 'upload') {
    const h = requireHandler(atomic, 'browser_file_upload');
    if (!h) return fail('UNSUPPORTED_TOOL:browser_manage');
    const paths = Array.isArray(p.paths)
      ? p.paths.map(String)
      : typeof p.file_path === 'string' && p.file_path
        ? [p.file_path]
        : [];
    const target = String(p.target ?? p.selector ?? '');
    return h(
      subJob(job, {
        paths,
        ...(paths.length === 1 ? { file_path: paths[0] } : {}),
        target,
        selector: String(p.selector ?? target)
      })
    );
  }
  if (action === 'close') {
    const h = requireHandler(atomic, 'browser_close');
    if (!h) return fail('UNSUPPORTED_TOOL:browser_manage');
    return h(subJob(job, {}));
  }
  return fail(`INVALID_ARGUMENT: unknown browser_manage action '${String(p.action || '')}'`);
}

/**
 * Build the four consolidated handlers bound to the given atomic handlers.
 * The returned map is merged over the atomic registry so the new tool names
 * advertise as capabilities and dispatch here; every branch delegates to an
 * existing atomic handler and returns its standard envelope untouched.
 * @param {Record<string, unknown>} atomicHandlers granular handler registry
 */
export function makeConsolidatedHandlers(atomicHandlers) {
  const atomic =
    atomicHandlers && typeof atomicHandlers === 'object' ? atomicHandlers : {};
  return {
    log_stream: (/** @type {unknown} */ job) => logStream(job, atomic),
    service_manage: (/** @type {unknown} */ job) => serviceManage(job, atomic),
    process_manage: (/** @type {unknown} */ job) => processManage(job, atomic),
    browser_manage: (/** @type {unknown} */ job) => browserManage(job, atomic)
  };
}
