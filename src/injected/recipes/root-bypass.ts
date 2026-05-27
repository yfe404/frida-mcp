/**
 * Root-detection bypass recipe.
 *
 * Derivative of @dzonerzy/fridantiroot + objection's root-bypass agent.
 * Patches:
 *   - java.io.File constructor for known su paths (returns a sentinel "missing")
 *   - Runtime.exec("su"...) → throws IOException so callers fall through
 *   - Build.TAGS test-keys override → "release-keys"
 *
 * Opt-in only: do NOT install on attach.
 */

import { recipePrelude, recipeAsyncInstall } from "./common.js";

const SU_PATHS = [
  "/system/bin/su",
  "/system/xbin/su",
  "/sbin/su",
  "/system/app/Superuser.apk",
  "/data/local/su",
  "/data/local/bin/su",
  "/data/local/xbin/su",
  "/system/sd/xbin/su",
  "/system/usr/we-need-root/su",
  "/system/bin/.ext/.su",
  "/system/etc/init.d/99SuperSUDaemon",
  "/dev/com.koushikdutta.superuser.daemon/",
  "/system/app/Kinguser.apk",
  "/system/app/SuperSU.apk",
  "/sbin/.magisk",
];

export function bypassRootDetectionJS(where?: string): string {
  const suSet = JSON.stringify(SU_PATHS);

  const installBody = `
    var SU_PATHS = ${suSet};
    try {
      var File = Java.use('java.io.File');
      var origExists = File.exists;
      File.exists.implementation = function () {
        var p = '' + this.getAbsolutePath();
        for (var i = 0; i < SU_PATHS.length; i++) {
          if (p === SU_PATHS[i]) {
            __mcpEmit({ type: 'root_bypass.file.exists', path: p, returned: false });
            return false;
          }
        }
        return origExists.call(this);
      };
    } catch (e) { __mcpEmit({ type: 'root_bypass.error', at: 'File.exists', err: String(e) }); }

    try {
      var Runtime = Java.use('java.lang.Runtime');
      var execStrOv = Runtime.exec.overload('java.lang.String');
      execStrOv.implementation = function (cmd) {
        if (('' + cmd).indexOf('su') !== -1) {
          __mcpEmit({ type: 'root_bypass.runtime.exec.blocked', cmd: '' + cmd });
          throw Java.use('java.io.IOException').$new('cannot run program "' + cmd + '": Permission denied');
        }
        return execStrOv.call(this, cmd);
      };
    } catch (e) { __mcpEmit({ type: 'root_bypass.error', at: 'Runtime.exec', err: String(e) }); }

    try {
      var Build = Java.use('android.os.Build');
      Build.TAGS.value = 'release-keys';
    } catch (e) { __mcpEmit({ type: 'root_bypass.error', at: 'Build.TAGS', err: String(e) }); }
  `;

  return `(function() {
  ${recipePrelude(where)}
  ${recipeAsyncInstall(installBody, "bypass_root_detection")}
})();`;
}
