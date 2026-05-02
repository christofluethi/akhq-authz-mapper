/*
 * Test harness for akhq-authz-mapper.js.
 *
 * Keycloak runs the script with a Java/Nashorn-style binding (Java.type, a
 * `user` object backed by UserModel, a `print` function, etc.). Here we
 * recreate just enough of that environment in a Node.js vm context to run
 * the actual script source unmodified, then return its `exports` value
 * along with everything it logged.
 */

'use strict';

const fs   = require('node:fs');
const path = require('node:path');
const vm   = require('node:vm');

const SCRIPT_PATH = path.resolve(
    __dirname,
    '..',
    'src',
    'main',
    'resources',
    'akhq-authz-mapper.js'
);
const SCRIPT_SRC = fs.readFileSync(SCRIPT_PATH, 'utf8');

/** Minimal stand-in for java.util.ArrayList. */
function makeArrayList() {
    const arr = [];
    arr.add  = (v) => { arr.push(v); return true; };
    arr.size = ()  => arr.length;
    arr.get  = (i) => arr[i];
    return arr;
}

/** Minimal stand-in for java.util.HashMap. */
function makeHashMap() {
    const data = new Map();
    return {
        put:    (k, v) => { data.set(k, v); return null; },
        get:    (k)    => (data.has(k) ? data.get(k) : null),
        keySet: ()     => Array.from(data.keys()).join(','),
        // Internal handle for converters/assertions in tests.
        _data:  data,
    };
}

/**
 * Run the mapper against a list of group names (or null to simulate the
 * `entra_groups` attribute being absent).
 *
 * Returns { result, logs } where:
 *   - result is the raw HashMap-shaped object the script assigned to
 *     `exports`
 *   - logs is an array of strings the script emitted via print()
 *
 * opts:
 *   username:         override user.getUsername() (default "testuser")
 *   debug:            shorthand - true sets system property
 *                     "akhq.mapper.debug" = "true". Default true so existing
 *                     log-checking tests keep working.
 *   realmAttributes:  { [name]: string } - exposed via realm.getAttribute(name)
 *                     If non-empty, a `realm` binding is provided to the script.
 *   systemProperties: { [name]: string } - exposed via java.lang.System.getProperty
 */
function runMapper(groups, opts = {}) {
    const username = opts.username || 'testuser';

    // System properties: start from caller-provided, then apply the
    // `debug` shorthand if not already explicitly set.
    const sysProps = Object.assign({}, opts.systemProperties || {});
    if (!('akhq.mapper.debug' in sysProps)) {
        const debugDefault = opts.debug !== undefined ? !!opts.debug : true;
        if (debugDefault) sysProps['akhq.mapper.debug'] = 'true';
    }

    const realmAttrs = Object.assign({}, opts.realmAttributes || {});
    const realmProvided =
        opts.realmAttributes !== undefined || // caller explicitly opted in
        false;

    const SystemMock = {
        getProperty(name) {
            return Object.prototype.hasOwnProperty.call(sysProps, name)
                ? sysProps[name]
                : null;
        },
    };

    const Java = {
        type(t) {
            if (t === 'java.util.ArrayList') return function () { return makeArrayList(); };
            if (t === 'java.util.HashMap')   return function () { return makeHashMap();   };
            if (t === 'java.lang.System')    return SystemMock;
            throw new Error('Unexpected Java.type call: ' + t);
        },
    };

    let groupsList = null;
    if (groups != null) {
        groupsList = makeArrayList();
        for (const g of groups) groupsList.add(g);
    }

    const user = {
        getUsername:  () => username,
        getAttribute: (name) => (name === 'entra_groups' ? groupsList : null),
    };

    const logs = [];
    const sandbox = {
        Java,
        user,
        print: (msg) => { logs.push(String(msg)); },
        // Pre-declare so the script's top-level `exports = result;` writes
        // here (it would otherwise create an implicit global on the context,
        // which also works, but being explicit avoids surprises).
        exports: undefined,
    };

    if (realmProvided) {
        sandbox.realm = {
            getAttribute(name) {
                return Object.prototype.hasOwnProperty.call(realmAttrs, name)
                    ? realmAttrs[name]
                    : null;
            },
        };
    }

    vm.createContext(sandbox);
    vm.runInContext(SCRIPT_SRC, sandbox, { filename: SCRIPT_PATH });

    return { result: sandbox.exports, logs };
}

/**
 * Convert HashMap/ArrayList-shaped objects produced by the script into
 * plain JS objects/arrays so we can use deepEqual assertions.
 */
function toPlain(v) {
    if (v == null) return v;
    if (Array.isArray(v)) {
        // Both our ArrayList mock (an array with extra methods) and a
        // plain array are handled identically here.
        return v.map(toPlain);
    }
    if (typeof v === 'object') {
        // HashMap mock?
        if (typeof v.put === 'function' && v._data instanceof Map) {
            const out = {};
            for (const [k, val] of v._data.entries()) out[k] = toPlain(val);
            return out;
        }
        // ArrayList-mocked-as-array would have hit the Array.isArray branch.
        // Anything else is a plain object literal.
        const out = {};
        for (const k of Object.keys(v)) out[k] = toPlain(v[k]);
        return out;
    }
    return v;
}

module.exports = { runMapper, toPlain, SCRIPT_PATH };
