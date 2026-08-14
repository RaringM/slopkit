(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const SETTINGS_KEY = "slopkit:settings";
    const ATTEMPTS_KEY = "slopkit:stats";
    const SETTINGS_VERSION = 4;
    const ATTEMPTS_VERSION = 3;
    const POST_EXPLOIT_VERSION = 1;
    const KERNEL_STATE_PREFIX = "slopkit:kernel-state:";
    const BOOT_GUARD_PREFIX = "slopkit:kernel-boot-guard:";
    const RECOVERY_REQUEST_PREFIX = "slopkit:post-exploit-request:";
    const RECOVERY_ARM_PREFIX = "slopkit:post-exploit-arm:";
    const MAX_DETAIL_RECORDS = 128;
    const MAX_COUNT = Number.MAX_SAFE_INTEGER;
    const EXPLOIT_ORDER = Object.freeze(["poops", "lapse", "p2jb"]);
    const DEFAULT_SETTINGS = Object.freeze({
        version: SETTINGS_VERSION,
        exploit: "poops",
        autoLaunchAutoloader: false,
        detailedDiagnostics: false,
        language: "auto"
    });

    function owns(value, key) {
        return Object.prototype.hasOwnProperty.call(value, key);
    }

    function configuredStorage(options) {
        if (options && owns(options, "storage")) return options.storage;
        try { return root.localStorage || null; }
        catch { return null; }
    }

    function configuredSessionStorage(options) {
        if (options && owns(options, "sessionStorage"))
            return options.sessionStorage;
        try { return root.sessionStorage || null; }
        catch { return null; }
    }

    function readStorage(storage, key) {
        if (!storage || typeof storage.getItem !== "function")
            return { available: false, value: null };
        try {
            return { available: true, value: storage.getItem(key) };
        } catch {
            return { available: false, value: null };
        }
    }

    function writeStorage(storage, key, value) {
        if (!storage || typeof storage.setItem !== "function") return false;
        try {
            const encoded = JSON.stringify(value);
            storage.setItem(key, encoded);
            return typeof storage.getItem === "function"
                && storage.getItem(key) === encoded;
        } catch {
            return false;
        }
    }

    function removeStorage(storage, key) {
        if (!storage || typeof storage.removeItem !== "function"
                || typeof storage.getItem !== "function") return false;
        try {
            storage.removeItem(key);
            return storage.getItem(key) === null;
        } catch {
            return false;
        }
    }

    function parseObject(raw) {
        if (typeof raw !== "string") return null;
        try {
            const value = JSON.parse(raw);
            return value && typeof value === "object" && !Array.isArray(value)
                ? value : null;
        } catch {
            return null;
        }
    }

    function validExploit(value) {
        const normalized = typeof value === "string"
            ? value.trim().toLowerCase() : "";
        return /^[a-z0-9][a-z0-9_-]{0,63}$/.test(normalized)
            ? normalized : null;
    }

    function validSettingExploit(value) {
        const normalized = validExploit(value);
        return EXPLOIT_ORDER.includes(normalized)
            ? normalized : null;
    }

    function validFirmware(value) {
        const normalized = typeof value === "string" ? value.trim() : "";
        return normalized && normalized.length <= 32
            && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(normalized)
            ? normalized : null;
    }

    function validAttemptId(value) {
        const normalized = typeof value === "string" ? value.trim() : "";
        return normalized && normalized.length <= 160
            && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(normalized)
            ? normalized : null;
    }

    function safeText(value, maximum) {
        if (typeof value !== "string") return null;
        const normalized = value.trim();
        return normalized ? normalized.slice(0, maximum) : null;
    }

    function recoveryToken() {
        const words = new Uint32Array(4);
        try {
            if (root.crypto && typeof root.crypto.getRandomValues === "function")
                root.crypto.getRandomValues(words);
            else throw new Error("crypto unavailable");
        } catch {
            for (let index = 0; index < words.length; ++index)
                words[index] = (Math.random() * 0x100000000) >>> 0;
        }
        return Array.from(words, function (word) {
            return word.toString(16).padStart(8, "0");
        }).join("");
    }

    function validRecoveryToken(value) {
        return typeof value === "string" && /^[a-f0-9]{32}$/i.test(value)
            ? value.toLowerCase() : null;
    }

    function copyAttemptContext(target, source) {
        for (const field of ["buildId", "profileRevision", "engineRevision",
            "runtimeRevision", "mode"]) {
            const value = safeText(source && source[field], 120);
            if (value) target[field] = value;
        }
        const runtimeDigest = safeText(source?.runtimeDigest, 64);
        if (/^[a-f0-9]{64}$/.test(runtimeDigest || ""))
            target.runtimeDigest = runtimeDigest;
        return target;
    }

    function mergeAttemptContext(target, source) {
        let changed = false;
        for (const field of ["buildId", "profileRevision", "engineRevision",
            "runtimeRevision", "mode"]) {
            if (target[field]) continue;
            const value = safeText(source && source[field], 120);
            if (!value) continue;
            target[field] = value;
            changed = true;
        }
        if (!target.runtimeDigest
                && /^[a-f0-9]{64}$/.test(source?.runtimeDigest || "")) {
            target.runtimeDigest = source.runtimeDigest;
            changed = true;
        }
        return changed;
    }

    function validStage(value) {
        const normalized = typeof value === "string"
            ? value.trim().toLowerCase() : "";
        return /^(renderer|kernel|seal|loader|action)$/.test(normalized)
            ? normalized : null;
    }

    function normalizeStages(value) {
        if (!Array.isArray(value)) return [];
        return Array.from(new Set(value.map(validStage).filter(Boolean))).sort();
    }

    function validMilestone(value) {
        const normalized = typeof value === "string"
            ? value.trim().toLowerCase() : "";
        return ATTEMPT_MILESTONES.has(normalized) ? normalized : null;
    }

    function normalizeMilestones(value) {
        if (!Array.isArray(value)) return [];
        return Array.from(new Set(value.map(validMilestone)
            .filter(Boolean)));
    }

    function validRecoveryDisposition(value) {
        return ["safe-normal-reboot", "dirty-cold-power-cycle", "sealed"]
            .includes(value) ? value : null;
    }

    function count(value) {
        const number = Number(value);
        if (!Number.isFinite(number) || number <= 0) return 0;
        return Math.min(MAX_COUNT, Math.floor(number));
    }

    function addCount(left, right) {
        return Math.min(MAX_COUNT, count(left) + count(right));
    }

    function timestamp(value) {
        const number = Number(value);
        return Number.isFinite(number) && number >= 0
            ? Math.min(MAX_COUNT, Math.floor(number)) : 0;
    }

    function cloneSettings(settings) {
        return {
            version: SETTINGS_VERSION,
            exploit: settings.exploit,
            autoLaunchAutoloader: settings.autoLaunchAutoloader,
            detailedDiagnostics: settings.detailedDiagnostics,
            language: settings.language
        };
    }

    function normalizeLanguage(value) {
        if (typeof value !== "string") return null;
        const normalized = value.trim().replace(/_/g, "-").toLowerCase();
        if (normalized === "auto") return normalized;
        return /^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$/.test(normalized)
            ? normalized : null;
    }

    function sanitizeSettings(value) {
        const source = value && typeof value === "object" ? value : {};
        const exploit = validSettingExploit(source.exploit);
        const language = normalizeLanguage(source.language);
        const autoLaunchAutoloader
            = typeof source.autoLaunchAutoloader === "boolean"
                ? source.autoLaunchAutoloader
                : typeof source.autoLaunchPayloadManager === "boolean"
                    ? source.autoLaunchPayloadManager
                    : source.autoSendPayload === true;
        const detailedDiagnostics
            = typeof source.detailedDiagnostics === "boolean"
                ? source.detailedDiagnostics
                : DEFAULT_SETTINGS.detailedDiagnostics;
        return {
            version: SETTINGS_VERSION,
            exploit: exploit || DEFAULT_SETTINGS.exploit,
            autoLaunchAutoloader,
            detailedDiagnostics,
            language: language || DEFAULT_SETTINGS.language
        };
    }

    function readSettings(storage, persistMigration) {
        const stored = readStorage(storage, SETTINGS_KEY);
        if (!stored.available || stored.value === null)
            return cloneSettings(DEFAULT_SETTINGS);

        const parsed = parseObject(stored.value);
        const settings = sanitizeSettings(parsed);
        const current = parsed && parsed.version === SETTINGS_VERSION;
        const future = parsed && Number.isInteger(parsed.version)
            && parsed.version > SETTINGS_VERSION;
        const canonical = current
            && JSON.stringify(parsed) === JSON.stringify(settings);
        if (persistMigration && !future && (!current || !canonical))
            writeStorage(storage, SETTINGS_KEY, settings);
        return settings;
    }

    function applySettingsPatch(current, patch) {
        const next = cloneSettings(current);
        if (!patch || typeof patch !== "object" || Array.isArray(patch))
            return next;

        if (owns(patch, "exploit")) {
            const exploit = validSettingExploit(patch.exploit);
            if (exploit) next.exploit = exploit;
        }
        if (owns(patch, "autoLaunchAutoloader")
                && typeof patch.autoLaunchAutoloader === "boolean")
            next.autoLaunchAutoloader = patch.autoLaunchAutoloader;
        else if (owns(patch, "autoLaunchPayloadManager")
                && typeof patch.autoLaunchPayloadManager === "boolean")
            next.autoLaunchAutoloader = patch.autoLaunchPayloadManager;
        else if (owns(patch, "autoSendPayload")
                && typeof patch.autoSendPayload === "boolean")
            next.autoLaunchAutoloader = patch.autoSendPayload;
        if (owns(patch, "detailedDiagnostics")
                && typeof patch.detailedDiagnostics === "boolean")
            next.detailedDiagnostics = patch.detailedDiagnostics;
        if (owns(patch, "language")) {
            const language = normalizeLanguage(patch.language);
            if (language) next.language = language;
        }
        return next;
    }

    function createSettings(options) {
        const storage = configuredStorage(options);
        return Object.freeze({
            load() {
                return readSettings(storage, true);
            },
            update(patch) {
                const next = applySettingsPatch(
                    readSettings(storage, false), patch);
                if (!writeStorage(storage, SETTINGS_KEY, next))
                    throw new Error("persistent settings storage is unavailable");
                return cloneSettings(next);
            }
        });
    }

    function emptyAttempts() {
        // Buckets keep long-lived aggregate counts; records make begin/finish
        // idempotent and retain enough context to recover an interrupted page.
        return { version: ATTEMPTS_VERSION, buckets: [], records: [] };
    }

    function makeBucket(exploit, firmware) {
        return {
            exploit,
            firmware,
            attempts: 0,
            successes: 0,
            failures: 0,
            interrupted: 0,
            stages: {
                renderer: 0,
                kernel: 0,
                seal: 0,
                loader: 0,
                action: 0
            }
        };
    }

    function bucketIdentity(exploit, firmware) {
        return exploit + "\u0000" + firmware;
    }

    function findBucket(state, exploit, firmware) {
        for (const bucket of state.buckets) {
            if (bucket.exploit === exploit && bucket.firmware === firmware)
                return bucket;
        }
        return null;
    }

    function ensureBucket(state, exploit, firmware) {
        let bucket = findBucket(state, exploit, firmware);
        if (!bucket) {
            bucket = makeBucket(exploit, firmware);
            state.buckets.push(bucket);
        }
        return bucket;
    }

    function mergeBucket(state, source) {
        const exploit = validExploit(source && source.exploit);
        const firmware = validFirmware(source && source.firmware);
        if (!exploit || !firmware) return;
        const target = ensureBucket(state, exploit, firmware);
        target.attempts = addCount(target.attempts, source.attempts);
        target.successes = addCount(target.successes, source.successes);
        target.failures = addCount(target.failures, source.failures);
        target.interrupted = addCount(target.interrupted, source.interrupted);
        const sourceStages = source.stages && typeof source.stages === "object"
            ? source.stages : {};
        for (const stage of ["renderer", "kernel", "seal", "loader", "action"])
            target.stages[stage] = addCount(target.stages[stage],
                sourceStages[stage]);
        if (target.interrupted > target.failures)
            target.failures = target.interrupted;
        const completed = addCount(target.successes, target.failures);
        if (target.attempts < completed) target.attempts = completed;
    }

    function normalizeOutcome(value) {
        if (value === true) return "success";
        if (value === false) return "failure";
        const normalized = typeof value === "string"
            ? value.trim().toLowerCase() : "";
        if (["success", "succeeded", "complete", "completed"].includes(normalized))
            return "success";
        if (["failure", "failed", "error"].includes(normalized))
            return "failure";
        if (["interrupted", "abandoned", "recovered"].includes(normalized))
            return "interrupted";
        return null;
    }

    function sanitizeRecord(source) {
        if (!source || typeof source !== "object" || Array.isArray(source))
            return null;
        const id = validAttemptId(source.id || source.attemptId);
        const exploit = validExploit(source.exploit);
        const firmware = validFirmware(source.firmware);
        const status = source.status === "pending"
            ? "pending" : normalizeOutcome(source.status || source.outcome);
        if (!id || !exploit || !firmware || !status) return null;
        const record = {
            id,
            exploit,
            firmware,
            status,
            startedAt: timestamp(source.startedAt)
        };
        copyAttemptContext(record, source);
        record.stages = normalizeStages(source.stages);
        record.milestones = normalizeMilestones(source.milestones);
        if (status !== "pending") {
            record.finishedAt = timestamp(source.finishedAt);
            const terminalStage = safeText(source.terminalStage, 120);
            if (terminalStage) record.terminalStage = terminalStage;
            if (typeof source.rebootRequired === "boolean")
                record.rebootRequired = source.rebootRequired;
            const disposition = validRecoveryDisposition(
                source.recoveryDisposition);
            if (disposition) record.recoveryDisposition = disposition;
        }
        return record;
    }

    function reconcileRecords(state) {
        const recordCounts = Object.create(null);
        for (const record of state.records) {
            const key = bucketIdentity(record.exploit, record.firmware);
            let entry = recordCounts[key];
            if (!entry) {
                entry = recordCounts[key] = {
                    exploit: record.exploit,
                    firmware: record.firmware,
                    successes: 0,
                    failures: 0,
                    interrupted: 0,
                    pending: 0,
                    stages: {
                        renderer: 0, kernel: 0, seal: 0, loader: 0, action: 0
                    }
                };
            }
            if (record.status === "success") entry.successes++;
            else if (record.status === "failure") entry.failures++;
            else if (record.status === "interrupted") {
                entry.failures++;
                entry.interrupted++;
            } else entry.pending++;
            for (const stage of record.stages)
                entry.stages[stage]++;
        }
        for (const key of Object.keys(recordCounts)) {
            const entry = recordCounts[key];
            const bucket = ensureBucket(state, entry.exploit, entry.firmware);
            bucket.successes = Math.max(bucket.successes, entry.successes);
            bucket.failures = Math.max(bucket.failures, entry.failures);
            bucket.interrupted = Math.max(bucket.interrupted,
                entry.interrupted);
            bucket.attempts = Math.max(bucket.attempts,
                addCount(addCount(bucket.successes, bucket.failures),
                    entry.pending));
            for (const stage of Object.keys(entry.stages))
                bucket.stages[stage] = Math.max(bucket.stages[stage],
                    entry.stages[stage]);
        }
        for (const bucket of state.buckets) {
            if (bucket.interrupted > bucket.failures)
                bucket.failures = bucket.interrupted;
            const completed = addCount(bucket.successes, bucket.failures);
            if (bucket.attempts < completed) bucket.attempts = completed;
        }
    }

    function sanitizeVersionedAttempts(source) {
        const state = emptyAttempts();
        if (Array.isArray(source.buckets)) {
            for (const bucket of source.buckets) mergeBucket(state, bucket);
        }
        const seen = Object.create(null);
        if (Array.isArray(source.records)) {
            for (const candidate of source.records) {
                const record = sanitizeRecord(candidate);
                if (!record || seen[record.id]) continue;
                seen[record.id] = true;
                state.records.push(record);
            }
        }
        reconcileRecords(state);
        return compactRecords(state);
    }

    function migrateLegacyAttempts(source) {
        const state = emptyAttempts();
        if (!source || typeof source !== "object" || Array.isArray(source))
            return state;
        for (const key of Object.keys(source)) {
            const separator = key.indexOf(":");
            const value = source[key];
            if (separator < 1 || !value || typeof value !== "object"
                    || Array.isArray(value)) continue;
            mergeBucket(state, {
                exploit: key.slice(0, separator),
                firmware: key.slice(separator + 1),
                attempts: value.attempts,
                successes: value.successes,
                failures: value.failures,
                interrupted: value.interrupted
            });
        }
        return state;
    }

    function readAttempts(storage, persistMigration) {
        const stored = readStorage(storage, ATTEMPTS_KEY);
        if (!stored.available || stored.value === null) return emptyAttempts();
        const parsed = parseObject(stored.value);
        let state;
        let current = false;
        let future = false;
        if (parsed && parsed.version === ATTEMPTS_VERSION) {
            current = true;
            state = sanitizeVersionedAttempts(parsed);
        } else if (parsed && (parsed.version === 1 || parsed.version === 2)) {
            state = sanitizeVersionedAttempts(parsed);
        } else if (parsed && Number.isInteger(parsed.version)
                && parsed.version > ATTEMPTS_VERSION) {
            future = true;
            state = sanitizeVersionedAttempts(parsed);
        } else {
            state = migrateLegacyAttempts(parsed);
        }
        const canonical = current
            && JSON.stringify(parsed) === JSON.stringify(state);
        if (persistMigration && !future && (!current || !canonical))
            writeStorage(storage, ATTEMPTS_KEY, state);
        return state;
    }

    function cloneRecord(record) {
        const result = {
            id: record.id,
            exploit: record.exploit,
            firmware: record.firmware,
            status: record.status,
            startedAt: record.startedAt
        };
        copyAttemptContext(result, record);
        if (record.stages.length) result.stages = record.stages.slice();
        if (record.milestones.length)
            result.milestones = record.milestones.slice();
        if (record.status !== "pending") {
            result.finishedAt = record.finishedAt;
            if (record.terminalStage)
                result.terminalStage = record.terminalStage;
            if (typeof record.rebootRequired === "boolean")
                result.rebootRequired = record.rebootRequired;
            if (record.recoveryDisposition)
                result.recoveryDisposition = record.recoveryDisposition;
        }
        return result;
    }

    function normalizeFinishDetails(outcomeOrDetails, extraDetails) {
        const details = outcomeOrDetails && typeof outcomeOrDetails === "object"
            && !Array.isArray(outcomeOrDetails)
            ? Object.assign({}, outcomeOrDetails)
            : Object.assign({}, extraDetails || {}, { outcome: outcomeOrDetails });
        const outcome = normalizeOutcome(details.outcome || details.status);
        if (!outcome) throw new TypeError("attempt outcome is invalid");
        const result = { outcome };
        const terminalStage = safeText(details.terminalStage, 120);
        if (terminalStage) result.terminalStage = terminalStage;
        if (typeof details.rebootRequired === "boolean")
            result.rebootRequired = details.rebootRequired;
        result.stages = normalizeStages(details.stages);
        result.milestones = normalizeMilestones(details.milestones);
        const disposition = validRecoveryDisposition(
            details.recoveryDisposition);
        if (disposition) result.recoveryDisposition = disposition;
        return result;
    }

    function terminalize(state, record, details, finishedAt) {
        if (record.status !== "pending") return false;
        const bucket = ensureBucket(state, record.exploit, record.firmware);
        const previousStages = new Set(record.stages);
        record.status = details.outcome;
        record.finishedAt = finishedAt;
        if (details.terminalStage)
            record.terminalStage = details.terminalStage;
        if (typeof details.rebootRequired === "boolean")
            record.rebootRequired = details.rebootRequired;
        const reached = new Set(record.stages);
        for (const stage of details.stages) reached.add(stage);
        record.stages = Array.from(reached).sort();
        const milestones = new Set(record.milestones);
        for (const milestone of details.milestones) milestones.add(milestone);
        record.milestones = Array.from(milestones);
        if (details.recoveryDisposition)
            record.recoveryDisposition = details.recoveryDisposition;
        for (const stage of record.stages) {
            if (!previousStages.has(stage))
                bucket.stages[stage] = addCount(bucket.stages[stage], 1);
        }
        if (details.outcome === "success")
            bucket.successes = addCount(bucket.successes, 1);
        else {
            // Interrupted is a separately visible subset of all failures.
            bucket.failures = addCount(bucket.failures, 1);
            if (details.outcome === "interrupted")
                bucket.interrupted = addCount(bucket.interrupted, 1);
        }
        return true;
    }

    function compactRecords(state) {
        const pending = [];
        const terminal = [];
        for (const record of state.records) {
            if (record.status === "pending") pending.push(record);
            else terminal.push(record);
        }
        terminal.sort(function (left, right) {
            return right.finishedAt - left.finishedAt
                || right.startedAt - left.startedAt
                || right.id.localeCompare(left.id);
        });
        state.records = pending.concat(terminal.slice(0, MAX_DETAIL_RECORDS));
        return state;
    }

    function makeCountSummary(source) {
        const attempts = count(source.attempts);
        const successes = count(source.successes);
        const failures = count(source.failures);
        const interrupted = Math.min(failures, count(source.interrupted));
        const completed = Math.min(attempts, addCount(successes, failures));
        const pending = Math.max(0, attempts - completed);
        const rate = attempts > 0
            ? Math.round((successes / attempts) * 100) : null;
        return { attempts, successes, failures, interrupted,
            pending, completed, rate };
    }

    function makeFunnel(source) {
        const attempts = count(source.attempts);
        const result = { started: attempts };
        const stages = source.stages && typeof source.stages === "object"
            ? source.stages : {};
        for (const stage of ["renderer", "kernel", "seal", "loader", "action"])
            result[stage] = Math.min(attempts, count(stages[stage]));
        return result;
    }

    function addSummary(target, source) {
        target.attempts = addCount(target.attempts, source.attempts);
        target.successes = addCount(target.successes, source.successes);
        target.failures = addCount(target.failures, source.failures);
        target.interrupted = addCount(target.interrupted, source.interrupted);
        if (!target.stages) target.stages = {
            renderer: 0, kernel: 0, seal: 0, loader: 0, action: 0
        };
        const sourceStages = source.stages || {};
        for (const stage of Object.keys(target.stages))
            target.stages[stage] = addCount(target.stages[stage],
                sourceStages[stage]);
    }

    function summarize(state) {
        const totals = { attempts: 0, successes: 0, failures: 0,
            interrupted: 0,
            stages: { renderer: 0, kernel: 0, seal: 0, loader: 0, action: 0 } };
        const exploitTotals = Object.create(null);
        const sorted = state.buckets.slice().sort(function (left, right) {
            return left.exploit.localeCompare(right.exploit)
                || left.firmware.localeCompare(right.firmware);
        });
        for (const bucket of sorted) {
            addSummary(totals, bucket);
            let exploit = exploitTotals[bucket.exploit];
            if (!exploit) {
                exploit = exploitTotals[bucket.exploit] = {
                    exploit: bucket.exploit,
                    attempts: 0,
                    successes: 0,
                    failures: 0,
                    interrupted: 0,
                    stages: {
                        renderer: 0, kernel: 0, seal: 0, loader: 0, action: 0
                    },
                    firmwares: Object.create(null)
                };
            }
            addSummary(exploit, bucket);
            exploit.firmwares[bucket.firmware] = Object.assign({
                exploit: bucket.exploit,
                firmware: bucket.firmware
            }, makeCountSummary(bucket));
        }
        const exploits = Object.create(null);
        for (const name of Object.keys(exploitTotals).sort()) {
            const value = exploitTotals[name];
            exploits[name] = Object.assign({ exploit: name },
                makeCountSummary(value), { firmwares: value.firmwares,
                    funnel: makeFunnel(value) });
        }
        const pending = state.records.filter(function (record) {
            return record.status === "pending";
        }).map(cloneRecord).sort(function (left, right) {
            return left.startedAt - right.startedAt
                || left.id.localeCompare(right.id);
        });
        return {
            version: ATTEMPTS_VERSION,
            overall: makeCountSummary(totals),
            funnel: makeFunnel(totals),
            exploits,
            pending
        };
    }

    function defaultNow() {
        return Date.now();
    }

    function defaultAttemptId(now) {
        let suffix = "";
        try {
            if (root.crypto && typeof root.crypto.getRandomValues === "function") {
                const words = new Uint32Array(2);
                root.crypto.getRandomValues(words);
                suffix = Array.from(words, function (word) {
                    return word.toString(16).padStart(8, "0");
                }).join("");
            }
        } catch {}
        if (!suffix)
            suffix = Math.floor(Math.random() * 0x100000000)
                .toString(16).padStart(8, "0");
        return "attempt-" + now.toString(36) + "-" + suffix;
    }

    function createAttempts(options) {
        const configuration = options || {};
        const storage = configuredStorage(configuration);
        const clock = typeof configuration.now === "function"
            ? configuration.now : defaultNow;
        const makeId = typeof configuration.makeId === "function"
            ? configuration.makeId : defaultAttemptId;

        function now() {
            try { return timestamp(clock()); }
            catch { return timestamp(defaultNow()); }
        }

        function begin(details) {
            if (!details || typeof details !== "object"
                    || Array.isArray(details))
                throw new TypeError("attempt details are required");
            const exploit = validExploit(details.exploit);
            const firmware = validFirmware(details.firmware);
            const startedAt = now();
            const requestedId = details.attemptId || details.id;
            const id = validAttemptId(requestedId || makeId(startedAt));
            if (!id || !exploit || !firmware)
                throw new TypeError("attempt identity is invalid");

            const state = readAttempts(storage, true);
            const existing = state.records.find(function (record) {
                return record.id === id;
            });
            if (existing) {
                if (existing.exploit !== exploit
                        || existing.firmware !== firmware)
                    throw new Error("attempt id already belongs to another run");
                if (mergeAttemptContext(existing, details)
                        && !writeStorage(storage, ATTEMPTS_KEY, state))
                    throw new Error("persistent attempt storage is unavailable");
                return cloneRecord(existing);
            }

            const record = copyAttemptContext({ id, exploit, firmware,
                status: "pending", startedAt }, details);
            record.stages = [];
            record.milestones = [];
            state.records.push(record);
            const bucket = ensureBucket(state, exploit, firmware);
            bucket.attempts = addCount(bucket.attempts, 1);
            // Keep the persisted record order canonical at the write boundary.
            // Renderer warmup reads the same state from a sibling document;
            // that read must not need to move this pending record ahead of
            // older terminal records and trip the launcher's no-mutation gate.
            compactRecords(state);
            if (!writeStorage(storage, ATTEMPTS_KEY, state))
                throw new Error("persistent attempt storage is unavailable");
            return cloneRecord(record);
        }

        function finish(idValue, outcomeOrDetails, extraDetails) {
            const id = validAttemptId(idValue);
            if (!id) throw new TypeError("attempt id is invalid");
            const details = normalizeFinishDetails(
                outcomeOrDetails, extraDetails);
            const state = readAttempts(storage, true);
            const record = state.records.find(function (candidate) {
                return candidate.id === id;
            });
            if (!record) return null;
            if (terminalize(state, record, details, now())) {
                compactRecords(state);
                if (!writeStorage(storage, ATTEMPTS_KEY, state))
                    throw new Error("persistent attempt storage is unavailable");
            }
            return cloneRecord(record);
        }

        function reach(idValue, stageValue) {
            const id = validAttemptId(idValue);
            const stage = validStage(stageValue);
            if (!id || !stage)
                throw new TypeError("attempt stage identity is invalid");
            const state = readAttempts(storage, true);
            const record = state.records.find(function (candidate) {
                return candidate.id === id;
            });
            if (!record || record.stages.includes(stage))
                return record ? cloneRecord(record) : null;
            record.stages.push(stage);
            record.stages.sort();
            const bucket = ensureBucket(state, record.exploit, record.firmware);
            bucket.stages[stage] = addCount(bucket.stages[stage], 1);
            if (!writeStorage(storage, ATTEMPTS_KEY, state))
                throw new Error("persistent attempt storage is unavailable");
            return cloneRecord(record);
        }

        function milestone(idValue, milestoneValue) {
            const id = validAttemptId(idValue);
            const code = validMilestone(milestoneValue);
            if (!id || !code)
                throw new TypeError("attempt milestone identity is invalid");
            const state = readAttempts(storage, true);
            const record = state.records.find(function (candidate) {
                return candidate.id === id;
            });
            if (!record || record.status !== "pending"
                    || record.milestones.includes(code))
                return record ? cloneRecord(record) : null;
            record.milestones.push(code);
            if (!writeStorage(storage, ATTEMPTS_KEY, state))
                throw new Error("persistent attempt storage is unavailable");
            return cloneRecord(record);
        }

        function summaries() {
            return summarize(readAttempts(storage, true));
        }

        function recover(recoveryOptions) {
            const recovery = recoveryOptions || {};
            const hasFilter = owns(Object(recovery), "attemptId")
                || owns(Object(recovery), "id");
            const filter = validAttemptId(
                recovery.attemptId || recovery.id || "");
            if (hasFilter && !filter)
                throw new TypeError("recovery attempt id is invalid");
            const resolver = typeof recovery.resolve === "function"
                ? recovery.resolve : null;
            let fallback;
            try {
                fallback = normalizeFinishDetails({
                    outcome: recovery.outcome || "interrupted",
                    terminalStage: recovery.terminalStage,
                    rebootRequired: recovery.rebootRequired,
                    recoveryDisposition: recovery.recoveryDisposition,
                    stages: recovery.stages,
                    milestones: recovery.milestones
                });
            } catch {
                fallback = { outcome: "interrupted", stages: [], milestones: [] };
            }

            const state = readAttempts(storage, true);
            const recovered = [];
            let changed = false;
            for (const record of state.records) {
                if (record.status !== "pending" || (filter && record.id !== filter))
                    continue;
                let details = fallback;
                if (resolver) {
                    let resolved;
                    try { resolved = resolver(cloneRecord(record)); }
                    catch { resolved = null; }
                    if (resolved === null || typeof resolved === "undefined")
                        continue;
                    try { details = normalizeFinishDetails(resolved); }
                    catch { continue; }
                }
                if (terminalize(state, record, details, now())) {
                    changed = true;
                    recovered.push(cloneRecord(record));
                }
            }

            let orphaned = 0;
            if (!filter) {
                const tracked = Object.create(null);
                for (const record of state.records) {
                    if (record.status !== "pending") continue;
                    const key = bucketIdentity(record.exploit, record.firmware);
                    tracked[key] = (tracked[key] || 0) + 1;
                }
                for (const bucket of state.buckets) {
                    const summary = makeCountSummary(bucket);
                    const key = bucketIdentity(bucket.exploit, bucket.firmware);
                    const missing = Math.max(0,
                        summary.pending - (tracked[key] || 0));
                    if (!missing) continue;
                    orphaned = addCount(orphaned, missing);
                    const outcome = resolver ? "interrupted" : fallback.outcome;
                    if (outcome === "success")
                        bucket.successes = addCount(bucket.successes, missing);
                    else {
                        bucket.failures = addCount(bucket.failures, missing);
                        if (outcome === "interrupted")
                            bucket.interrupted = addCount(
                                bucket.interrupted, missing);
                    }
                    changed = true;
                }
            }
            if (changed) {
                compactRecords(state);
                if (!writeStorage(storage, ATTEMPTS_KEY, state))
                    throw new Error("persistent attempt storage is unavailable");
            }
            return { recovered, orphaned, changed };
        }

        function reset() {
            return removeStorage(storage, ATTEMPTS_KEY);
        }

        return Object.freeze({ begin, finish, reach, milestone, summaries,
            recover, reset });
    }

    function postExploitKey(firmware) {
        return `${KERNEL_STATE_PREFIX}${firmware}`;
    }

    function bootGuardKey(firmware) {
        return `${BOOT_GUARD_PREFIX}${firmware}`;
    }

    function validBootIdentity(value) {
        return typeof value === "string"
            && /^boottime-v1:(?:[a-f0-9]{2}){8,32}$/i.test(value)
            ? value.toLowerCase() : null;
    }

    function completionIdentity(source) {
        if (!source || typeof source !== "object" || Array.isArray(source))
            return null;
        const firmware = validFirmware(source.firmware);
        const exploit = validSettingExploit(source.exploit);
        const attemptId = validAttemptId(source.attemptId);
        const bootId = validBootIdentity(source.bootId);
        const buildId = safeText(source.buildId, 120);
        const profileRevision = safeText(source.profileRevision, 120);
        const engineRevision = safeText(source.engineRevision, 120);
        const runtimeRevision = safeText(source.runtimeRevision, 120);
        if (source.postExploitVersion !== POST_EXPLOIT_VERSION
                || source.state !== "complete" || source.mode !== "full"
                || source.rebootRequired !== false
                || source.recoveryDisposition !== "sealed"
                || !firmware || !exploit || !attemptId || !bootId
                || !buildId || !profileRevision || !engineRevision
                || !runtimeRevision)
            return null;
        const identity = { firmware, exploit, attemptId, bootId, buildId,
            profileRevision, engineRevision, runtimeRevision };
        if (source.runtimeDigest !== undefined) {
            const runtimeDigest = safeText(source.runtimeDigest, 64);
            if (!/^[a-f0-9]{64}$/.test(runtimeDigest || "")) return null;
            identity.runtimeDigest = runtimeDigest;
        }
        return identity;
    }

    function sameCompletionIdentity(left, right) {
        const a = completionIdentity(left) || left;
        const b = completionIdentity(right) || right;
        if (!a || !b) return false;
        for (const field of ["firmware", "exploit", "attemptId", "bootId",
            "buildId", "profileRevision", "engineRevision",
            "runtimeRevision", "runtimeDigest"]) {
            if ((a[field] || null) !== (b[field] || null)) return false;
        }
        return true;
    }

    function readPostExploitRecord(firmware, options) {
        const local = configuredStorage(options);
        const stored = readStorage(local, postExploitKey(firmware));
        return stored.available ? parseObject(stored.value) : null;
    }

    function inspectPostExploit(firmwareValue, options) {
        const firmware = validFirmware(firmwareValue);
        if (!firmware) return { status: "invalid", reason: "firmware" };
        const local = configuredStorage(options);
        const stored = readStorage(local, postExploitKey(firmware));
        if (!stored.available)
            return { status: "invalid", reason: "storage" };
        if (stored.value === null) return { status: "none" };
        const record = parseObject(stored.value);
        if (!record || record.firmware !== firmware
                || !completionIdentity(record))
            return { status: "invalid", reason: "completion-record",
                record };

        const bootGuard = parseObject(readStorage(local,
            bootGuardKey(firmware)).value);
        if (!bootGuard || bootGuard.state !== "kernel-attempt-started"
                || bootGuard.firmware !== record.firmware
                || bootGuard.exploit !== record.exploit
                || bootGuard.attemptId !== record.attemptId
                || bootGuard.bootId !== record.bootId)
            return { status: "invalid", reason: "boot-guard", record };

        const attempts = readAttempts(local, false);
        const attempt = attempts.records.find(function (candidate) {
            return candidate.id === record.attemptId;
        });
        if (!attempt || attempt.status !== "success"
                || attempt.firmware !== record.firmware
                || attempt.exploit !== record.exploit
                || attempt.terminalStage !== "elfldr-ready"
                || attempt.rebootRequired !== false
                || attempt.recoveryDisposition !== "sealed"
                || attempt.buildId !== record.buildId
                || attempt.profileRevision !== record.profileRevision
                || attempt.engineRevision !== record.engineRevision
                || attempt.runtimeRevision !== record.runtimeRevision
                || (attempt.runtimeDigest || null)
                    !== (record.runtimeDigest || null))
            return { status: "invalid", reason: "attempt", record };

        const expectedBuild = safeText(options?.buildId, 120);
        if (expectedBuild && expectedBuild !== record.buildId)
            return { status: "incompatible", reason: "build", record,
                bootGuard, attempt: cloneRecord(attempt) };
        const expectedBinding = options?.profileBinding;
        if (expectedBinding) {
            for (const field of ["exploit", "profileRevision",
                "engineRevision", "runtimeRevision", "runtimeDigest"]) {
                if ((expectedBinding[field] || null)
                        !== (record[field] || null))
                    return { status: "incompatible", reason: field, record,
                        bootGuard, attempt: cloneRecord(attempt) };
            }
        }
        if (record.postExploit?.unavailable)
            return { status: "disabled",
                reason: record.postExploit.unavailable.reason || "unavailable",
                record, bootGuard, attempt: cloneRecord(attempt) };
        return { status: "ready", record, bootGuard,
            attempt: cloneRecord(attempt) };
    }

    function sealPostExploit(details, options) {
        if (!details || typeof details !== "object" || Array.isArray(details))
            throw new TypeError("post-exploit completion details are required");
        const firmware = validFirmware(details.firmware);
        if (!firmware) throw new TypeError("post-exploit firmware is invalid");
        const local = configuredStorage(options);
        const previous = readPostExploitRecord(firmware, options) || {};
        const source = Object.assign({}, previous, details, {
            postExploitVersion: POST_EXPLOIT_VERSION,
            state: "complete", mode: "full", rebootRequired: false,
            recoveryDisposition: "sealed"
        });
        const identity = completionIdentity(source);
        if (!identity)
            throw new TypeError("post-exploit completion identity is invalid");
        const now = new Date().toISOString();
        const record = Object.assign({}, source, identity, {
            postExploitVersion: POST_EXPLOIT_VERSION,
            state: "complete", mode: "full", rebootRequired: false,
            recoveryDisposition: "sealed",
            completedAt: safeText(source.completedAt, 64) || now,
            updated: now,
            postExploit: {}
        });
        if (!writeStorage(local, postExploitKey(firmware), record))
            throw new Error("persistent post-exploit completion is unavailable");
        return record;
    }

    function updatePostExploit(firmwareValue, updater, options) {
        const firmware = validFirmware(firmwareValue);
        const local = configuredStorage(options);
        const record = readPostExploitRecord(firmware, options);
        const identity = completionIdentity(record);
        if (!firmware || !identity)
            throw new Error("sealed post-exploit completion is unavailable");
        const next = Object.assign({}, record, {
            postExploit: Object.assign({}, record.postExploit || {})
        });
        updater(next.postExploit, next);
        if (!sameCompletionIdentity(identity, next)
                || next.state !== "complete" || next.mode !== "full"
                || next.rebootRequired !== false
                || next.recoveryDisposition !== "sealed")
            throw new Error("post-exploit completion identity changed");
        next.updated = new Date().toISOString();
        if (!writeStorage(local, postExploitKey(firmware), next))
            throw new Error("post-exploit completion update failed");
        return next;
    }

    function notePostExploitAction(firmware, details, options) {
        const actionId = safeText(details?.actionId, 64);
        const outcome = details?.outcome;
        if (!actionId || !["sent", "failed"].includes(outcome))
            throw new TypeError("post-exploit action result is invalid");
        return updatePostExploit(firmware, function (metadata) {
            metadata.lastAction = {
                actionId, outcome, at: new Date().toISOString()
            };
            if (Number.isSafeInteger(details.bytes) && details.bytes >= 0)
                metadata.lastAction.bytes = details.bytes;
        }, options);
    }

    function disablePostExploit(firmware, reasonValue, options) {
        const reason = safeText(reasonValue, 80);
        if (!reason) throw new TypeError("post-exploit disable reason is invalid");
        return updatePostExploit(firmware, function (metadata, record) {
            metadata.unavailable = {
                reason, bootId: record.bootId, at: new Date().toISOString()
            };
        }, options);
    }

    function retirePostExploit(firmwareValue, expectedBootId,
            observedBootId, options) {
        const firmware = validFirmware(firmwareValue);
        const expected = validBootIdentity(expectedBootId);
        const observed = validBootIdentity(observedBootId);
        const local = configuredStorage(options);
        const record = readPostExploitRecord(firmware, options);
        if (!firmware || !expected || !observed || expected === observed
                || completionIdentity(record)?.bootId !== expected)
            throw new Error("post-exploit reboot proof is invalid");

        // A sealed completion supersedes any older attempt that was left
        // pending by a lost renderer navigation. Once a different native boot
        // is verified, close those historical records before removing the
        // completion so the launcher cannot resurrect one as a fresh latch.
        // Pending attempts newer than the successful completion remain intact
        // and continue to fail closed.
        const attemptsState = readAttempts(local, true);
        const completedAttempt = attemptsState.records.find(function (attempt) {
            return attempt.id === record.attemptId
                && attempt.status === "success";
        });
        const recoveredAttemptIds = [];
        if (completedAttempt) {
            const attempts = createAttempts(
                Object.assign({}, options, { storage: local }));
            const superseded = attempts.summaries().pending.filter(
                function (attempt) {
                    return attempt.firmware === firmware
                        && attempt.startedAt <= completedAttempt.startedAt;
                });
            for (const attempt of superseded) {
                const milestones = Array.isArray(attempt.milestones)
                    ? attempt.milestones : [];
                const result = attempts.recover({
                    attemptId: attempt.id,
                    outcome: "interrupted",
                    terminalStage: milestones.length
                        ? milestones[milestones.length - 1]
                        : "verified-reboot",
                    rebootRequired: false,
                    recoveryDisposition: "safe-normal-reboot"
                });
                for (const recovered of result.recovered)
                    recoveredAttemptIds.push(recovered.id);
            }
        }
        if (!removeStorage(local, postExploitKey(firmware)))
            throw new Error("stale post-exploit completion could not be retired");
        return { firmware, attemptId: record.attemptId,
            previousBootId: expected, observedBootId: observed,
            recoveredAttemptIds };
    }

    function requestRecord(source) {
        if (!source || source.version !== POST_EXPLOIT_VERSION
                || source.kind !== "request") return null;
        const token = validRecoveryToken(source.token);
        const firmware = validFirmware(source.firmware);
        const attemptId = validAttemptId(source.attemptId);
        const actionId = safeText(source.actionId, 64);
        const purpose = ["launch", "verify-boot"].includes(source.purpose)
            ? source.purpose : null;
        if (!token || !firmware || !attemptId
                || actionId !== "unified-autoloader" || !purpose) return null;
        return Object.assign({}, source, { token, firmware, attemptId,
            actionId, purpose });
    }

    function createRecoveryRequest(details, options) {
        const inspection = inspectPostExploit(details?.firmware, options);
        if (!["ready", "disabled"].includes(inspection.status))
            throw new Error("post-exploit recovery is not available");
        const actionId = details?.actionId || "unified-autoloader";
        if (actionId !== "unified-autoloader")
            throw new TypeError("post-exploit recovery action is invalid");
        const purpose = details?.purpose || (inspection.status === "disabled"
            ? "verify-boot" : "launch");
        if (!["launch", "verify-boot"].includes(purpose)
                || (purpose === "launch" && inspection.status !== "ready"))
            throw new TypeError("post-exploit recovery purpose is invalid");
        const session = configuredSessionStorage(options);
        const token = recoveryToken();
        const record = {
            version: POST_EXPLOIT_VERSION, kind: "request", token,
            firmware: inspection.record.firmware,
            attemptId: inspection.record.attemptId,
            actionId,
            purpose,
            createdAt: Date.now()
        };
        if (!writeStorage(session, `${RECOVERY_REQUEST_PREFIX}${token}`, record))
            throw new Error("post-exploit recovery request could not be armed");
        return token;
    }

    function consumeRecoveryRequest(tokenValue, options) {
        const token = validRecoveryToken(tokenValue);
        const session = configuredSessionStorage(options);
        if (!token) return null;
        const key = `${RECOVERY_REQUEST_PREFIX}${token}`;
        const record = requestRecord(parseObject(readStorage(session, key).value));
        if (!record || !removeStorage(session, key)) return null;
        const inspection = inspectPostExploit(record.firmware, options);
        if (!["ready", "disabled"].includes(inspection.status)
                || inspection.record.attemptId !== record.attemptId)
            return null;
        return Object.assign({}, record, { completion: inspection.record });
    }

    function armRecord(source) {
        if (!source || source.version !== POST_EXPLOIT_VERSION
                || source.kind !== "arm"
                || source.mode !== "post-exploit-recovery") return null;
        const token = validRecoveryToken(source.token);
        const firmware = validFirmware(source.firmware);
        const exploit = validSettingExploit(source.exploit);
        const attemptId = validAttemptId(source.attemptId);
        const bootId = validBootIdentity(source.bootId);
        const actionId = safeText(source.actionId, 64);
        const purpose = ["launch", "verify-boot"].includes(source.purpose)
            ? source.purpose : null;
        const buildId = safeText(source.buildId, 120);
        const profileRevision = safeText(source.profileRevision, 120);
        const engineRevision = safeText(source.engineRevision, 120);
        const runtimeRevision = safeText(source.runtimeRevision, 120);
        if (!token || !firmware || !exploit || !attemptId || !bootId
                || actionId !== "unified-autoloader" || !purpose || !buildId
                || !profileRevision || !engineRevision || !runtimeRevision)
            return null;
        const record = Object.assign({}, source, { token, firmware, exploit,
            attemptId, bootId, actionId, buildId, profileRevision,
            engineRevision, runtimeRevision, purpose });
        if (source.runtimeDigest !== undefined) {
            if (!/^[a-f0-9]{64}$/.test(source.runtimeDigest)) return null;
            record.runtimeDigest = source.runtimeDigest;
        }
        return record;
    }

    function createRecoveryArm(details, options) {
        const completion = details?.completion;
        const identity = completionIdentity(completion);
        if (!identity || details?.actionId !== "unified-autoloader"
                || !["launch", "verify-boot"].includes(details?.purpose))
            throw new TypeError("post-exploit recovery arm is invalid");
        const inspection = inspectPostExploit(identity.firmware, options);
        if (!["ready", "disabled"].includes(inspection.status)
                || (details.purpose === "launch"
                    && inspection.status !== "ready")
                || !sameCompletionIdentity(inspection.record, completion))
            throw new Error("post-exploit completion changed before arming");
        const session = configuredSessionStorage(options);
        const token = recoveryToken();
        const record = Object.assign({
            version: POST_EXPLOIT_VERSION, kind: "arm", token,
            mode: "post-exploit-recovery",
            actionId: details.actionId, purpose: details.purpose,
            createdAt: Date.now()
        }, identity);
        if (!writeStorage(session, `${RECOVERY_ARM_PREFIX}${token}`, record))
            throw new Error("post-exploit renderer arm could not be stored");
        return token;
    }

    function readRecoveryArm(tokenValue, options) {
        const token = validRecoveryToken(tokenValue);
        if (!token) return null;
        const session = configuredSessionStorage(options);
        return armRecord(parseObject(readStorage(session,
            `${RECOVERY_ARM_PREFIX}${token}`).value));
    }

    function validRecoveryWarmup(value) {
        return value?.version === 1
            && value.method === "unarmed-precritical-placement-pairs-v1"
            && value.historyRead === false
            && value.historyReadIntercepts === 1
            && value.reportIntercepts === 1
            && value.released === true
            && value.placementPairs === 4;
    }

    function attestRecoveryArm(tokenValue, warmup, options) {
        const token = validRecoveryToken(tokenValue);
        const session = configuredSessionStorage(options);
        const record = readRecoveryArm(token, options);
        if (!record || warmup?.historyRead !== false
                || warmup.historyReadIntercepts !== 1
                || warmup.reportIntercepts !== 1
                || warmup.released !== true || warmup.placementPairs !== 4)
            throw new Error("post-exploit renderer warmup is invalid");
        record.rendererWarmup = {
            version: 1, method: "unarmed-precritical-placement-pairs-v1",
            historyRead: false, historyReadIntercepts: 1,
            reportIntercepts: 1, released: true, placementPairs: 4
        };
        if (!writeStorage(session, `${RECOVERY_ARM_PREFIX}${token}`, record))
            throw new Error("post-exploit renderer warmup could not be stored");
        return record;
    }

    function consumeRecoveryArm(tokenValue, expected, options) {
        const token = validRecoveryToken(tokenValue);
        const session = configuredSessionStorage(options);
        const record = readRecoveryArm(token, options);
        if (!record || !validRecoveryWarmup(record.rendererWarmup)) return null;
        for (const field of ["firmware", "exploit", "attemptId", "bootId",
            "buildId", "profileRevision", "engineRevision",
            "runtimeRevision", "runtimeDigest", "actionId", "purpose"]) {
            if ((expected?.[field] || null) !== (record[field] || null))
                return null;
        }
        const inspection = inspectPostExploit(record.firmware, options);
        if (!["ready", "disabled"].includes(inspection.status)
                || !sameCompletionIdentity(inspection.record, record)
                || !removeStorage(session, `${RECOVERY_ARM_PREFIX}${token}`))
            return null;
        return record;
    }

    function clearRecoverySession(options) {
        const session = configuredSessionStorage(options);
        if (!session || typeof session.length !== "number") return false;
        try {
            for (let index = session.length - 1; index >= 0; --index) {
                const key = session.key(index);
                if (key?.startsWith(RECOVERY_REQUEST_PREFIX)
                        || key?.startsWith(RECOVERY_ARM_PREFIX))
                    session.removeItem(key);
            }
            return true;
        } catch { return false; }
    }

    const PostExploitRecovery = Object.freeze({
        VERSION: POST_EXPLOIT_VERSION,
        REQUEST_PREFIX: RECOVERY_REQUEST_PREFIX,
        ARM_PREFIX: RECOVERY_ARM_PREFIX,
        inspect: inspectPostExploit,
        seal: sealPostExploit,
        noteAction: notePostExploitAction,
        disable: disablePostExploit,
        retire: retirePostExploit,
        createRequest: createRecoveryRequest,
        consumeRequest: consumeRecoveryRequest,
        createArm: createRecoveryArm,
        readArm: readRecoveryArm,
        attestArm: attestRecoveryArm,
        consumeArm: consumeRecoveryArm,
        clearSession: clearRecoverySession
    });

    const Settings = Object.freeze({
        KEY: SETTINGS_KEY,
        VERSION: SETTINGS_VERSION,
        DEFAULTS: DEFAULT_SETTINGS,
        create: createSettings,
        load(options) { return createSettings(options).load(); },
        update(patch, options) {
            return createSettings(options).update(patch);
        }
    });

    const ExploitSelection = Object.freeze({
        ORDER: EXPLOIT_ORDER,
        choose(current, available) {
            const choices = new Set(Array.from(available || [], validSettingExploit)
                .filter(Boolean));
            const selected = validSettingExploit(current);
            if (selected && choices.has(selected)) return selected;
            return EXPLOIT_ORDER.find((exploit) => choices.has(exploit)) || null;
        }
    });

    const Attempts = Object.freeze({
        KEY: ATTEMPTS_KEY,
        VERSION: ATTEMPTS_VERSION,
        create: createAttempts,
        begin(details, options) {
            return createAttempts(options).begin(details);
        },
        finish(id, outcomeOrDetails, detailsOrOptions, options) {
            if (outcomeOrDetails && typeof outcomeOrDetails === "object"
                    && !Array.isArray(outcomeOrDetails))
                return createAttempts(detailsOrOptions).finish(
                    id, outcomeOrDetails);
            return createAttempts(options).finish(
                id, outcomeOrDetails, detailsOrOptions);
        },
        reach(id, stage, options) {
            return createAttempts(options).reach(id, stage);
        },
        milestone(id, code, options) {
            return createAttempts(options).milestone(id, code);
        },
        summaries(options) {
            return createAttempts(options).summaries();
        },
        recover(options) {
            return createAttempts(options).recover(options);
        },
        reset(options) {
            return createAttempts(options).reset();
        }
    });

    NS.Settings = Settings;
    NS.Attempts = Attempts;
    NS.ExploitSelection = ExploitSelection;
    NS.PostExploitRecovery = PostExploitRecovery;
    if (typeof module !== "undefined" && module.exports)
        module.exports = { Settings, Attempts, ExploitSelection,
            PostExploitRecovery };
})(typeof globalThis !== "undefined" ? globalThis : this);
