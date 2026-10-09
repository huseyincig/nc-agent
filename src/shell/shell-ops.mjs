// Phase 5 refactor: pure shell-construction helpers extracted from core/client.mjs.
// Zero coupling (params/globals only). Behavior unchanged.
export /**
 * @param {string} command @param {string} [platform]
 * How to spawn one shell string. On win32 the command travels verbatim:
 * libuv's default quoting mangles embedded double quotes (cmd.exe has no
 * backslash escapes), which silently breaks e.g. powershell -Command "...".
 * Win32 child forces UTF-8 codepage (65001) to prevent mojibake on non-ASCII output.
 * `windowsVerbatimArguments` is a no-op on POSIX.
 */
function shellInvocation(command, platform = process.platform) {
  if (platform === 'win32') {
    const winCommand = command ? `chcp 65001 >NUL & ${command}` : 'chcp 65001 >NUL';
    return {
      file: process.env.ComSpec || process.env.COMSPEC || 'cmd.exe',
      args: ['/d', '/s', '/c', winCommand],
      windowsVerbatimArguments: true
    };
  }
  return { file: '/bin/bash', args: ['-lc', command], windowsVerbatimArguments: false };
}

export function shellChildDetached(platform = process.platform) {
  return platform !== 'win32';
}
