"use strict";

// BP at sub_1E150 entry: rcx = FLT_CALLBACK_DATA*. Chase ->Iopb->TargetFileObject->FileName,
// match suffix "test.txt" (case-insensitive on the wide path).
function isTargetCreate() {
    try {
        var rcx = host.currentThread.Registers.User.rcx;
        var data = host.createTypedObject(rcx, "fltmgr", "_FLT_CALLBACK_DATA");
        var fileName = data.Iopb.TargetFileObject.FileName;
        var len = fileName.Length;
        var nlen = (typeof len === 'object' && len.compareTo) ? len.asNumber() : len;
        if (nlen < 16) return 0;
        var bufAddr = fileName.Buffer.address;
        var last8 = host.memory.readMemoryValues(bufAddr.add(nlen - 8), 8, 1);
        // Compare wide chars case-insensitively to ".txt"
        if ((last8[0] | 0x20) !== 0x2e || last8[1] !== 0x00 ||
            (last8[2] | 0x20) !== 0x74 || last8[3] !== 0x00 ||
            (last8[4] | 0x20) !== 0x78 || last8[5] !== 0x00 ||
            (last8[6] | 0x20) !== 0x74 || last8[7] !== 0x00) {
            return 0;
        }
        var prev8 = host.memory.readMemoryValues(bufAddr.add(nlen - 16), 8, 1);
        // Compare wide chars case-insensitively to "test"
        var match = (prev8[0] | 0x20) === 0x74 && prev8[1] === 0x00 &&
                    (prev8[2] | 0x20) === 0x65 && prev8[3] === 0x00 &&
                    (prev8[4] | 0x20) === 0x73 && prev8[5] === 0x00 &&
                    (prev8[6] | 0x20) === 0x74 && prev8[7] === 0x00;
        return match ? 1 : 0;
    } catch (e) {
        return 0;
    }
}

function alwaysFalse() { return 0; }
function alwaysTrue() { return 1; }

// Documented .scriptrun pattern (Microsoft JS-debugger-scripting docs).
// Bound to a BP via:  bp ADDR ".scriptrun C:\\path\\to\\bp_helpers.js"
// Engine runs invokeScript() at every BP hit. If we don't want to break,
// we explicitly issue gc; otherwise leaving without ExecuteCommand keeps
// the engine at break for the user.
function invokeScript() {
    var ctl = host.namespace.Debugger.Utility.Control;
    if (!isTargetCreate()) {
        ctl.ExecuteCommand("gc");
    }
    // else: leave at break (test.txt match)
}

function initializeScript() {
    return [
        new host.functionAlias(isTargetCreate, "isTargetCreate"),
        new host.functionAlias(alwaysFalse, "alwaysFalse"),
        new host.functionAlias(alwaysTrue, "alwaysTrue")
    ];
}
