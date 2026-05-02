'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');

const { runMapper, toPlain } = require('./harness');

function bindingFor(role, appid, stage) {
    return {
        role,
        patterns: [appid + '-.*'],
        clusters: [stage],
    };
}

/**
 * Pretty-print the mapper's output before asserting on it. The JSON shows
 * exactly what would land in the OIDC token claim configured on the
 * Keycloak protocol mapper (typically the "groups" claim).
 */
function dump(label, plain) {
    console.log('--- ' + label + ' ---');
    console.log(JSON.stringify(plain, null, 2));
}

test('Reader-only group emits topic-reader and group-reader', () => {
    const { result } = runMapper(['Entra-Group-Id-APP-TEST-TopicReader']);
    const plain = toPlain(result);
    dump('Reader-only', plain);
    assert.deepEqual(plain, {
        'app-test': [
            bindingFor('topic-reader', 'app', 'test'),
            bindingFor('group-reader', 'app', 'test'),
        ],
    });
});

test('Writer-only group emits topic-writer (additional role)', () => {
    const { result } = runMapper(['Entra-Group-Id-APP-TEST-TopicWriter']);
    const plain = toPlain(result);
    dump('Writer-only', plain);
    assert.deepEqual(plain, {
        'app-test': [
            bindingFor('topic-writer', 'app', 'test'),
        ],
    });
});

test('Admin group emits topic-admin and group-admin', () => {
    const { result } = runMapper(['Entra-Group-Id-OTHER-PROD-TopicAdmin']);
    const plain = toPlain(result);
    dump('Admin-only', plain);
    assert.deepEqual(plain, {
        'other-prod': [
            bindingFor('topic-admin', 'other', 'prod'),
            bindingFor('group-admin', 'other', 'prod'),
        ],
    });
});

test('Reader + Writer for same appid-stage merge without duplicate permissions', () => {
    const { result } = runMapper([
        'Entra-Group-Id-APP-TEST-TopicReader',
        'Entra-Group-Id-APP-TEST-TopicWriter',
    ]);
    const plain = toPlain(result);
    dump('Reader + Writer (same appid-stage)', plain);

    // Single bucket
    assert.deepEqual(Object.keys(plain), ['app-test']);

    const roles = plain['app-test'].map((b) => b.role);

    // Three distinct roles, in the expected order
    assert.deepEqual(roles, ['topic-reader', 'group-reader', 'topic-writer']);

    // Explicit no-duplicates check (the ask)
    assert.equal(new Set(roles).size, roles.length, 'no duplicate roles');

    // Each binding has correct patterns/clusters
    for (const b of plain['app-test']) {
        assert.deepEqual(b.patterns, ['app-.*']);
        assert.deepEqual(b.clusters, ['test']);
    }
});

test('Writer + Reader (reverse order) produces the same set of roles', () => {
    const { result } = runMapper([
        'Entra-Group-Id-APP-TEST-TopicWriter',
        'Entra-Group-Id-APP-TEST-TopicReader',
    ]);
    const plain = toPlain(result);
    dump('Writer + Reader (reverse order)', plain);
    const roles = plain['app-test'].map((b) => b.role).sort();
    assert.deepEqual(roles, ['group-reader', 'topic-reader', 'topic-writer']);
});

test('Reader + Writer + Admin for same appid-stage all merge without duplicates', () => {
    const { result } = runMapper([
        'Entra-Group-Id-APP-TEST-TopicReader',
        'Entra-Group-Id-APP-TEST-TopicWriter',
        'Entra-Group-Id-APP-TEST-TopicAdmin',
    ]);
    const plain = toPlain(result);
    dump('Reader + Writer + Admin', plain);
    const roles = plain['app-test'].map((b) => b.role);
    assert.deepEqual(
        roles.slice().sort(),
        ['group-admin', 'group-reader', 'topic-admin', 'topic-reader', 'topic-writer']
    );
    assert.equal(new Set(roles).size, roles.length, 'no duplicate roles');
});

test('Same Reader group listed twice does not duplicate roles', () => {
    const { result, logs } = runMapper([
        'Entra-Group-Id-APP-TEST-TopicReader',
        'Entra-Group-Id-APP-TEST-TopicReader',
    ]);
    const plain = toPlain(result);
    dump('Reader x2 (deduped)', plain);
    assert.deepEqual(plain, {
        'app-test': [
            bindingFor('topic-reader', 'app', 'test'),
            bindingFor('group-reader', 'app', 'test'),
        ],
    });
    assert.ok(
        logs.some((l) => l.includes('already present')),
        'expected dedup log line'
    );
});

test('Different appid-stage combinations produce independent buckets', () => {
    const { result } = runMapper([
        'Entra-Group-Id-APP-TEST-TopicReader',
        'Entra-Group-Id-APP-PROD-TopicReader',
        'Entra-Group-Id-OTHER-TEST-TopicWriter',
    ]);
    const plain = toPlain(result);
    dump('Multiple appid-stage buckets', plain);
    assert.deepEqual(Object.keys(plain).sort(), ['app-prod', 'app-test', 'other-test']);

    assert.deepEqual(plain['app-test'].map((b) => b.role), ['topic-reader', 'group-reader']);
    assert.deepEqual(plain['app-prod'].map((b) => b.role), ['topic-reader', 'group-reader']);
    assert.deepEqual(plain['other-test'].map((b) => b.role), ['topic-writer']);

    // Patterns and clusters are scoped to each bucket's appid/stage
    assert.deepEqual(plain['other-test'][0].patterns, ['other-.*']);
    assert.deepEqual(plain['other-test'][0].clusters, ['test']);
});

test('Group names that do not match the regex are skipped', () => {
    const { result, logs } = runMapper([
        'Some-Random-Group',
        'Entra-Group-Id-APP-TEST-Banana',         // wrong suffix
        'Entra-Id-Group-APP-TEST-TopicReader',    // old prefix variant
        'Entra-Group-Id--TEST-TopicReader',        // empty appid
    ]);
    const plain = toPlain(result);
    dump('No matching groups', plain);
    assert.deepEqual(plain, {});
    assert.ok(logs.some((l) => l.includes('no match, skipping')));
});

test('Casing is normalised: appid, stage, and permission are lowercased in output', () => {
    const { result } = runMapper(['Entra-Group-Id-MixedCase-StAgE-TopicReader']);
    const plain = toPlain(result);
    dump('MixedCase input -> lowercased output', plain);
    assert.deepEqual(Object.keys(plain), ['mixedcase-stage']);
    assert.deepEqual(plain['mixedcase-stage'][0].patterns, ['mixedcase-.*']);
    assert.deepEqual(plain['mixedcase-stage'][0].clusters, ['stage']);
});

test('Null entra_groups attribute returns an empty result', () => {
    const { result, logs } = runMapper(null);
    const plain = toPlain(result);
    dump('Null entra_groups attribute', plain);
    assert.deepEqual(plain, {});
    assert.ok(logs.some((l) => l.includes("'entra_groups' is null")));
});

test('Empty entra_groups attribute returns an empty result', () => {
    const { result } = runMapper([]);
    const plain = toPlain(result);
    dump('Empty entra_groups attribute', plain);
    assert.deepEqual(plain, {});
});

test('Debug output is emitted with the AKHQ-AuthZ-Mapper prefix when enabled', () => {
    const { result, logs } = runMapper(['Entra-Group-Id-APP-TEST-TopicReader']);
    dump('Debug-output check', toPlain(result));
    assert.ok(logs.length > 0, 'script produced log output');
    assert.ok(logs.every((l) => l.startsWith('[AKHQ-AuthZ-Mapper]')));
    assert.ok(logs.some((l) => l.includes('--- start ---')));
    assert.ok(logs.some((l) => l.includes('--- end ---')));
    assert.ok(logs.some((l) => l.includes("matched: appid=app, stage=test, permission=reader")));
});

// ---------------------------------------------------------------------------
// Debug-toggle tests
// ---------------------------------------------------------------------------

test('Debug disabled by default produces no log output but still maps correctly', () => {
    const { result, logs } = runMapper(
        ['Entra-Group-Id-APP-TEST-TopicReader'],
        { debug: false }
    );
    const plain = toPlain(result);
    dump('Debug disabled - mapping still works', plain);
    assert.deepEqual(plain, {
        'app-test': [
            bindingFor('topic-reader', 'app', 'test'),
            bindingFor('group-reader', 'app', 'test'),
        ],
    });
    assert.deepEqual(logs, [], 'no log lines should be emitted when debug is off');
});

test('Debug enabled via realm attribute "akhq_mapper_debug=true"', () => {
    const { result, logs } = runMapper(
        ['Entra-Group-Id-APP-TEST-TopicReader'],
        {
            debug: false, // do NOT set the system property
            realmAttributes: { akhq_mapper_debug: 'true' },
        }
    );
    dump('Debug enabled via realm attribute', toPlain(result));
    assert.ok(logs.length > 0, 'logs should be produced');
    assert.ok(logs.some((l) => l.includes('--- start ---')));
});

test('Debug enabled via system property "akhq.mapper.debug=true"', () => {
    const { result, logs } = runMapper(
        ['Entra-Group-Id-APP-TEST-TopicReader'],
        {
            debug: false, // overridden by explicit systemProperties below
            systemProperties: { 'akhq.mapper.debug': 'true' },
        }
    );
    dump('Debug enabled via system property', toPlain(result));
    assert.ok(logs.length > 0, 'logs should be produced');
    assert.ok(logs.some((l) => l.includes('--- start ---')));
});

test('Realm attribute set to a non-"true" value does not enable debug', () => {
    const { logs } = runMapper(
        ['Entra-Group-Id-APP-TEST-TopicReader'],
        {
            debug: false,
            realmAttributes: { akhq_mapper_debug: 'yes' }, // not "true"
        }
    );
    assert.deepEqual(logs, [], 'only the literal string "true" enables debug');
});

test('Realm attribute "TRUE" (uppercase) also enables debug (case-insensitive)', () => {
    const { logs } = runMapper(
        ['Entra-Group-Id-APP-TEST-TopicReader'],
        {
            debug: false,
            realmAttributes: { akhq_mapper_debug: 'TRUE' },
        }
    );
    assert.ok(logs.length > 0, 'TRUE should enable debug');
});
