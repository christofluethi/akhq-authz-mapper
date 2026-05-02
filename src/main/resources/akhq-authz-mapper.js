/*
 * AKHQ Authorization Mapper for Keycloak
 *
 * Script-based OIDC Protocol Mapper that translates a user's "entra_groups"
 * attribute into the AKHQ "groups" claim structure.
 *
 * Group naming convention (Microsoft Entra ID):
 *   Entra-Group-Id-<APPID>-<STAGE>-Topic(Reader|Writer|Admin)
 *
 * Output structure (per AKHQ external-mapping format):
 *   {
 *     "<appid>-<stage>": [
 *       { "role": "topic-reader",  "patterns": ["<appid>-.*"], "clusters": ["<stage>"] },
 *       { "role": "group-reader",  "patterns": ["<appid>-.*"], "clusters": ["<stage>"] },
 *       { "role": "topic-writer",  "patterns": ["<appid>-.*"], "clusters": ["<stage>"] }, // if writer
 *       ...
 *     ]
 *   }
 *
 * The above object is returned as the value of whichever claim name the
 * Keycloak admin configures on the protocol mapper (typically "groups").
 *
 * Available bindings inside this script (provided by Keycloak):
 *   user, realm, token, userSession, keycloakSession, clientSessionCtx
 *
 * Debug logging:
 *   Disabled by default. Enable via either of:
 *     - realm attribute  "akhq_mapper_debug" = "true"   (runtime, per-realm)
 *     - JVM system prop  "akhq.mapper.debug" = "true"   (-Dakhq.mapper.debug=true)
 *   When enabled, every step is logged via print() with the [AKHQ-AuthZ-Mapper]
 *   prefix to the Keycloak server log.
 */

var ArrayList = Java.type("java.util.ArrayList");
var HashMap   = Java.type("java.util.HashMap");
var System    = Java.type("java.lang.System");

var LOG_PREFIX = "[AKHQ-AuthZ-Mapper]";

function isDebugEnabled() {
    // 1) realm attribute (runtime, no restart required)
    try {
        if (typeof realm !== "undefined" && realm !== null) {
            var realmAttr = realm.getAttribute("akhq_mapper_debug");
            if (realmAttr != null && String(realmAttr).toLowerCase() === "true") {
                return true;
            }
        }
    } catch (e) { /* realm binding unavailable - fall through */ }

    // 2) JVM system property (set with -Dakhq.mapper.debug=true at startup)
    try {
        var sysProp = System.getProperty("akhq.mapper.debug");
        if (sysProp != null && String(sysProp).toLowerCase() === "true") {
            return true;
        }
    } catch (e) { /* shouldn't happen */ }

    return false;
}

var DEBUG = isDebugEnabled();

function debug(msg) {
    // No-op unless debug logging was enabled via configuration.
    if (DEBUG) {
        print(LOG_PREFIX + " " + msg);
    }
}

debug("--- start ---");
debug("user=" + (typeof user !== "undefined" && user !== null ? user.getUsername() : "<null>"));

var result = new HashMap();

var groupsAttr = null;
try {
    groupsAttr = user.getAttribute("entra_groups");
} catch (e) {
    debug("ERROR reading 'entra_groups' attribute: " + e);
}

if (groupsAttr == null) {
    debug("attribute 'entra_groups' is null - nothing to map");
} else {
    debug("attribute 'entra_groups' has " + groupsAttr.size() + " entries");

    // Pattern matches: Entra-Group-Id-<APPID>-<STAGE>-Topic(Reader|Writer|Admin)
    var groupRegex = /^Entra-Group-Id-([A-Za-z0-9]+)-([A-Za-z0-9]+)-Topic(Reader|Writer|Admin)$/;

    for (var i = 0; i < groupsAttr.size(); i++) {
        var name = groupsAttr.get(i);
        debug("processing group[" + i + "]='" + name + "'");

        var match = name.match(groupRegex);
        if (!match) {
            debug("  -> no match, skipping");
            continue;
        }

        var appid      = match[1].toLowerCase();
        var stage      = match[2].toLowerCase();
        var permission = match[3].toLowerCase(); // reader | writer | admin

        var key     = appid + "-" + stage;
        var pattern = appid + "-.*";

        debug("  -> matched: appid=" + appid + ", stage=" + stage + ", permission=" + permission);
        debug("  -> key='" + key + "', pattern='" + pattern + "'");

        // Determine which AKHQ roles correspond to this Entra permission.
        // Reader  -> topic-reader, group-reader
        // Writer  -> topic-writer (additional to whatever Reader granted)
        // Admin   -> topic-admin,  group-admin
        var rolesToAdd;
        if (permission === "reader") {
            rolesToAdd = ["topic-reader", "group-reader"];
        } else if (permission === "writer") {
            rolesToAdd = ["topic-writer"];
        } else if (permission === "admin") {
            rolesToAdd = ["topic-admin", "group-admin"];
        } else {
            rolesToAdd = [];
        }

        // Get-or-create the bindings list for this appid-stage key.
        var bindings = result.get(key);
        if (bindings == null) {
            bindings = new ArrayList();
            result.put(key, bindings);
        }

        for (var r = 0; r < rolesToAdd.length; r++) {
            var role = rolesToAdd[r];

            // Skip if this role was already added (e.g. user is in both
            // Reader and Writer groups for the same appid-stage).
            var alreadyPresent = false;
            for (var b = 0; b < bindings.size(); b++) {
                if (String(bindings.get(b).get("role")) === role) {
                    alreadyPresent = true;
                    break;
                }
            }
            if (alreadyPresent) {
                debug("  -> role '" + role + "' already present for key '" + key + "', skipping");
                continue;
            }

            var patterns = new ArrayList();
            patterns.add(pattern);

            var clusters = new ArrayList();
            clusters.add(stage);

            var binding = new HashMap();
            binding.put("role",     role);
            binding.put("patterns", patterns);
            binding.put("clusters", clusters);

            bindings.add(binding);
            debug("  -> added binding: role='" + role + "' to key '" + key + "'");
        }
    }
}

debug("final result keys: " + result.keySet());
debug("--- end ---");

exports = result;
