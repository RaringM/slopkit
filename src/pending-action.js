(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const ACTION_ID = "browser-installer";
    const ENDPOINT = `/api/v1/actions/${ACTION_ID}`;
    const SESSION_KEY = "slopkit:pending-action";
    const ARM_PREFIX = "slopkit:arm:";
    const MAX_DESCRIPTOR_BYTES = 8192;
    const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
    const OUTER_FIELDS = Object.freeze([
        "id", "label", "path", "schema", "sha256", "size",
        "supportedFirmware"
    ]);

    function exactFields(value, fields) {
        if (!value || typeof value !== "object" || Array.isArray(value))
            return false;
        const actual = Object.keys(value).sort();
        const expected = fields.slice().sort();
        return actual.length === expected.length
            && actual.every((field, index) => field === expected[index]);
    }

    function validateLabel(value) {
        if (!value || typeof value !== "object" || Array.isArray(value))
            throw new Error("requested action localized label is invalid");
        const locales = Object.keys(value);
        if (!locales.length || locales.length > 16 || !locales.includes("en"))
            throw new Error("requested action localized label has no English fallback");
        for (const locale of locales) {
            const text = value[locale];
            if (!/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/.test(locale)
                    || typeof text !== "string" || text !== text.trim()
                    || !text || text.length > 80
                    || /[\x00-\x1f\x7f]/.test(text))
                throw new Error("requested action localized label entry is invalid");
        }
        return Object.assign({}, value);
    }

    function validateDescriptor(value, firmware) {
        if (!exactFields(value, OUTER_FIELDS) || value.schema !== 1
                || value.id !== ACTION_ID)
            throw new Error("requested action descriptor schema is invalid");
        const label = validateLabel(value.label);
        if (!Number.isSafeInteger(value.size) || value.size <= 0
                || value.size > MAX_ARTIFACT_BYTES
                || !/^[a-f0-9]{64}$/.test(value.sha256 || ""))
            throw new Error("requested action artifact lock is invalid");
        const expectedPath = `${ENDPOINT}/${value.sha256}.elf`;
        if (value.path !== expectedPath)
            throw new Error("requested action artifact path is invalid");
        if (!Array.isArray(value.supportedFirmware)
                || value.supportedFirmware.length === 0
                || value.supportedFirmware.length > 32
                || new Set(value.supportedFirmware).size
                    !== value.supportedFirmware.length
                || value.supportedFirmware.some((entry) =>
                    !/^\d{2}\.\d{2}$/.test(entry)))
            throw new Error("requested action firmware qualification is invalid");
        if (!/^\d{2}\.\d{2}$/.test(firmware || "")
                || !value.supportedFirmware.includes(firmware))
            throw new Error(`requested action is unavailable on firmware ${firmware || "unknown"}`);
        return Object.freeze({
            schema: 1,
            id: ACTION_ID,
            label: Object.freeze(label),
            supportedFirmware: Object.freeze(value.supportedFirmware.slice()),
            size: value.size,
            sha256: value.sha256,
            path: value.path
        });
    }

    function parseStored(raw, firmware) {
        try {
            const value = JSON.parse(raw || "null");
            if (!exactFields(value, ["descriptor", "schema"])
                    || value.schema !== 1)
                throw new Error("pending action session schema is invalid");
            return validateDescriptor(value.descriptor, firmware);
        } catch {
            return null;
        }
    }

    function load(firmware) {
        let raw = null;
        try { raw = root.sessionStorage.getItem(SESSION_KEY); }
        catch { return null; }
        if (!raw) return null;
        const descriptor = parseStored(raw, firmware);
        if (descriptor) return descriptor;
        try { root.sessionStorage.removeItem(SESSION_KEY); } catch {}
        return null;
    }

    function store(descriptor) {
        const encoded = JSON.stringify({ schema: 1, descriptor });
        root.sessionStorage.setItem(SESSION_KEY, encoded);
        if (root.sessionStorage.getItem(SESSION_KEY) !== encoded)
            throw new Error("pending action session readback failed");
        return descriptor;
    }

    function removeQueryParameter() {
        const current = new URL(root.location.href);
        current.searchParams.delete("post-action");
        const relative = current.pathname + current.search + current.hash;
        root.history.replaceState(root.history.state, "", relative);
    }

    async function fetchDescriptor(firmware) {
        const endpoint = new URL(ENDPOINT, root.location.href);
        if (endpoint.origin !== root.location.origin
                || endpoint.pathname !== ENDPOINT || endpoint.search
                || endpoint.hash)
            throw new Error("requested action endpoint is not same-origin");
        const response = await root.fetch(ENDPOINT, {
            cache: "no-store",
            credentials: "same-origin",
            headers: { Accept: "application/json" }
        });
        const responseUrl = new URL(response.url || endpoint.href,
            root.location.href);
        if (responseUrl.origin !== endpoint.origin
                || responseUrl.pathname !== ENDPOINT
                || responseUrl.search || responseUrl.hash)
            throw new Error("requested action descriptor redirected off its fixed endpoint");
        if (!response.ok)
            throw new Error(`requested action descriptor returned HTTP ${response.status}`);
        const contentType = response.headers?.get?.("content-type") || "";
        if (!/^application\/json(?:;|$)/i.test(contentType))
            throw new Error("requested action descriptor is not JSON");
        const text = await response.text();
        if (!text || text.length > MAX_DESCRIPTOR_BYTES)
            throw new Error("requested action descriptor size is invalid");
        let value;
        try { value = JSON.parse(text); }
        catch { throw new Error("requested action descriptor JSON is invalid"); }
        return validateDescriptor(value, firmware);
    }

    async function capture(firmware) {
        const current = new URL(root.location.href);
        const requested = current.searchParams.get("post-action");
        if (requested === null) return load(firmware);
        if (requested !== ACTION_ID) {
            removeQueryParameter();
            throw new Error("requested action identity is not allowed");
        }
        try {
            const descriptor = await fetchDescriptor(firmware);
            store(descriptor);
            return descriptor;
        } finally {
            // A rejected or unavailable fixed descriptor must not linger in
            // history and silently retry on every launcher reload.
            removeQueryParameter();
        }
    }

    function cancel() {
        try {
            root.sessionStorage.removeItem(SESSION_KEY);
            return root.sessionStorage.getItem(SESSION_KEY) === null;
        } catch { return false; }
    }

    function copyToArmRecord(record, firmware) {
        if (!record || typeof record !== "object" || Array.isArray(record))
            throw new Error("arm record is invalid");
        const descriptor = load(firmware);
        if (descriptor)
            record.requestedAction = JSON.parse(JSON.stringify(descriptor));
        return record;
    }

    function consumeCommitted(armToken, firmware) {
        if (!/^[a-f0-9]{32}$/.test(armToken || "")) return false;
        let arm;
        try {
            arm = JSON.parse(root.sessionStorage.getItem(
                `${ARM_PREFIX}${armToken}`) || "null");
        } catch { return false; }
        if (!arm?.requestedAction) return false;
        let armed;
        try { armed = validateDescriptor(arm.requestedAction, firmware); }
        catch { return false; }
        const pending = load(firmware);
        if (!pending || JSON.stringify(pending) !== JSON.stringify(armed))
            return false;
        return cancel();
    }

    function actionFromArmRecord(record, firmware) {
        if (!record?.requestedAction) return null;
        const descriptor = validateDescriptor(record.requestedAction, firmware);
        const locale = String(NS.I18n?.locale || "en");
        const label = descriptor.label[locale]
            || descriptor.label[locale.split("-")[0]]
            || descriptor.label.en;
        return Object.freeze({
            id: descriptor.id,
            kind: "requested",
            order: 0,
            titleKey: "runtime.requested.title",
            readyKey: "runtime.requested.run",
            sendingKey: "runtime.requested.sending",
            sentKey: "runtime.requested.sent",
            retryKey: "runtime.requested.retry",
            failedKey: "runtime.requested.failed",
            unavailableKey: "runtime.requested.unavailable",
            sentStatusKey: "runtime.requested.sentStatus",
            failedStatusKey: "runtime.requested.failedStatus",
            stageKey: "runtime.stage.startingRequestedAction",
            progressPrefix: "REQUESTED-ACTION",
            label,
            artifact: Object.freeze({
                path: descriptor.path,
                size: descriptor.size,
                sha256: descriptor.sha256
            }),
            firmwares: descriptor.supportedFirmware,
            optional: true,
            requested: true
        });
    }

    NS.PendingActions = Object.freeze({
        ACTION_ID, ENDPOINT, SESSION_KEY, validateDescriptor, capture, load,
        cancel, copyToArmRecord, consumeCommitted, actionFromArmRecord
    });
    if (typeof module !== "undefined" && module.exports)
        module.exports = NS.PendingActions;
})(typeof globalThis !== "undefined" ? globalThis : this);
