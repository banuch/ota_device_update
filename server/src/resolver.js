'use strict';
// =============================================================================
//  resolver.js  --  which firmware should this device run?
//
//    1. device.pinned_version set  -> that release (downgrade allowed)
//    2. otherwise                  -> current release of device.channel,
//                                     only if NEWER than what it runs
//    3. target == running version  -> no update
// =============================================================================

const VERSION_RE = /^(\d+)\.(\d+)\.(\d+)$/;

function parseVersion(v) {
  const m = VERSION_RE.exec(String(v || '').trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function isValidVersion(v) {
  return parseVersion(v) !== null;
}

/** -1 a<b, 0 equal, 1 a>b; throws on unparseable input. */
function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) throw new Error(`invalid version: ${!pa ? a : b}`);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

/**
 * @param {object} device         row from devices table
 * @param {string} currentVer     version the device reports it runs
 * @param {(name:string)=>string|null} channelVersion  channel -> release version
 * @returns {{target:string|null, reason:string}}
 */
function resolveTarget(device, currentVer, channelVersion) {
  if (device.pinned_version) {
    if (device.pinned_version === currentVer) return { target: null, reason: 'pinned_already_running' };
    return { target: device.pinned_version, reason: 'pinned' };
  }
  const chVer = channelVersion(device.channel);
  if (!chVer) return { target: null, reason: 'channel_has_no_release' };
  if (!isValidVersion(currentVer)) return { target: chVer, reason: 'channel_unparseable_current' };
  const cmp = compareVersions(chVer, currentVer);
  if (cmp > 0) return { target: chVer, reason: 'channel' };
  return { target: null, reason: cmp === 0 ? 'up_to_date' : 'running_newer_than_channel' };
}

module.exports = { parseVersion, isValidVersion, compareVersions, resolveTarget };
