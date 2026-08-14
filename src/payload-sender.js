(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};

    const SETTINGS_KEY = "slopkit:settings";
    const SEND_BUFFER_SIZE = 0x10000;
    const SEND_TIMEOUT_SECONDS = 15;
    const PAYLOAD_PORT = 9021;
    const EADDRINUSE = 48;
    const UNIFIED_AUTOLOADER = Object.freeze({
        id: "unified-autoloader",
        kind: "unifiedAutoloader",
        order: 10,
        titleKey: "runtime.autoloader.heading",
        readyKey: "runtime.autoloader.launch",
        sendingKey: "runtime.autoloader.launching",
        sentKey: "runtime.autoloader.sent",
        retryKey: "runtime.autoloader.retry",
        failedKey: "runtime.autoloader.failed",
        unavailableKey: "runtime.autoloader.unavailable",
        sentStatusKey: "runtime.status.autoloaderStarting",
        failedStatusKey: "runtime.autoloader.failedStatus",
        stageKey: "runtime.stage.startingAutoloader",
        progressPrefix: "PAYLOAD",
        artifact: Object.freeze({
            path: "payloads/ps5-unified-autoloader-v0.1.3-78a6f02.elf",
            size: 2510344,
            sha256: "f411cc69872d7bdfc1d5166b37e93cd31bffdce355ff204c74f787767a4acad8"
        }),
        autoSetting: "autoLaunchAutoloader",
        terminal: true
    });
    const ACTIONS = Object.freeze([UNIFIED_AUTOLOADER]);
    const AUTO_SETTINGS = new Set(["autoLaunchAutoloader"]);

    function validateActionRegistry(actions) {
        if (!Array.isArray(actions) || actions.length === 0)
            throw new Error("post-action registry is empty");
        const ids = new Set();
        const orders = new Set();
        let terminalOrder = null;
        for (const action of actions) {
            if (!action || typeof action !== "object")
                throw new Error("post-action descriptor is invalid");
            if (!/^[a-z][a-z0-9_-]{0,31}$/.test(action.id || "")
                    || ids.has(action.id))
                throw new Error("post-action identity is invalid or duplicated");
            ids.add(action.id);
            if (!Number.isSafeInteger(action.order) || orders.has(action.order))
                throw new Error("post-action order is invalid or duplicated");
            orders.add(action.order);
            for (const key of ["titleKey", "readyKey",
                "sendingKey", "sentKey", "retryKey", "failedKey",
                "unavailableKey", "stageKey", "progressPrefix"]) {
                if (typeof action[key] !== "string" || !action[key])
                    throw new Error(`${action.id} is missing ${key}`);
                if (key.endsWith("Key") && typeof NS.I18n?.t === "function"
                        && NS.I18n.t(action[key]) === action[key])
                    throw new Error(`${action.id} translation ${action[key]} is unavailable`);
            }
            for (const key of ["sentStatusKey", "failedStatusKey"]) {
                if (action[key] !== undefined
                        && (typeof action[key] !== "string" || !action[key]
                            || (typeof NS.I18n?.t === "function"
                                && NS.I18n.t(action[key]) === action[key])))
                    throw new Error(`${action.id} translation ${key} is unavailable`);
            }
            if (!action.artifact || typeof action.artifact.path !== "string"
                    || !action.artifact.path
                    || action.artifact.path.startsWith("/")
                    || action.artifact.path.includes(".."))
                throw new Error(`${action.id} artifact path is invalid`);
            if (!Number.isSafeInteger(action.artifact.size)
                    || action.artifact.size <= 0
                    || !/^[a-f0-9]{64}$/.test(action.artifact.sha256 || ""))
                throw new Error(`${action.id} artifact lock is invalid`);
            if (action.autoSetting !== undefined
                    && !AUTO_SETTINGS.has(action.autoSetting))
                throw new Error(`${action.id} auto setting is invalid`);
            if (action.firmwares !== undefined
                    && (!Array.isArray(action.firmwares)
                        || action.firmwares.length === 0
                        || new Set(action.firmwares).size
                            !== action.firmwares.length
                        || action.firmwares.some((firmware) =>
                            !/^\d{2}\.\d{2}$/.test(firmware))))
                throw new Error(`${action.id} firmware qualification is invalid`);
            if (action.optional === true && action.terminal === true)
                throw new Error(`${action.id} cannot be optional and terminal`);
            if (action.terminal === true) {
                if (terminalOrder !== null)
                    throw new Error("post-action registry has multiple terminal actions");
                terminalOrder = action.order;
            }
        }
        if (terminalOrder !== null && actions.some((action) =>
            action.order > terminalOrder))
            throw new Error("terminal post action must be ordered last");
        return true;
    }

    validateActionRegistry(ACTIONS);

    function actionSupportsFirmware(action, firmware) {
        return Boolean(action && /^\d{2}\.\d{2}$/.test(firmware || "")
            && (!Array.isArray(action.firmwares)
                || action.firmwares.includes(firmware)));
    }

    function loadSettings() {
        try {
            const raw = root.localStorage.getItem(SETTINGS_KEY);
            if (!raw) return {};
            return JSON.parse(raw);
        } catch { return {}; }
    }

    function resolveSettings() {
        const stored = typeof NS.Settings?.load === "function"
            ? NS.Settings.load() : loadSettings();
        const autoLaunchAutoloader
            = typeof stored.autoLaunchAutoloader === "boolean"
                ? stored.autoLaunchAutoloader
                : stored.autoLaunchPayloadManager === true
                    || stored.autoSendPayload === true;
        return {
            exploit: stored.exploit || "poops",
            autoLaunchAutoloader,
            payloadPath: UNIFIED_AUTOLOADER.artifact.path,
            action: UNIFIED_AUTOLOADER,
        };
    }

    class PayloadSender {
        constructor(nativeTransport, profile) {
            if (!NS.NativeBridge)
                throw new Error("native.js must be loaded before payload delivery");
            if (!nativeTransport || !nativeTransport.bridge)
                throw new Error("payload delivery requires a native transport");
            this.transport = nativeTransport;
            this.bridge = nativeTransport.bridge;
            this.profile = profile;
            this.sockaddr = null;
            this.optionBuf = null;
            this.timeoutBuf = null;
            this.sendBuf = null;
            this.hash = typeof NS.sha256Hex === "function"
                ? NS.sha256Hex : null;
        }

        allocateBuffers() {
            this.allocateSockaddr();
            const alloc = (size, align, label) =>
                this.transport.alloc(size, align, label);

            if (this.optionBuf) return;
            this.optionBuf = alloc(4, 4, "payload-sockopt");
            this.optionBuf.fill(0);
            this.optionBuf.put8(0, 1);

            this.timeoutBuf = alloc(0x10, 8, "payload-timeout");
            this.timeoutBuf.fill(0);
            this.timeoutBuf.put64(0, SEND_TIMEOUT_SECONDS);

            this.sendBuf = alloc(SEND_BUFFER_SIZE, 0x10, "payload-sendbuf");
        }

        allocateSockaddr() {
            if (this.sockaddr) return;
            if (typeof this.transport.alloc !== "function")
                throw new Error("payload delivery allocator is unavailable");
            this.sockaddr = this.transport.alloc(
                0x10, 4, "payload-sockaddr");
            this.sockaddr.fill(0);
            this.sockaddr.put8(0, 0x10);
            this.sockaddr.put8(1, 2);
            this.sockaddr.put8(2, (PAYLOAD_PORT >>> 8) & 0xff);
            this.sockaddr.put8(3, PAYLOAD_PORT & 0xff);
            this.sockaddr.put8(4, 127);
            this.sockaddr.put8(5, 0);
            this.sockaddr.put8(6, 0);
            this.sockaddr.put8(7, 1);
        }

        lastErrno() {
            try {
                const pointer = this.bridge.callOffset(
                    "native.exports.error", []);
                return this.bridge.memory.read32(pointer.toPointerNumber()) | 0;
            } catch { return null; }
        }

        probeExistingLoader() {
            this.allocateSockaddr();
            const K = this.profile.raw.kernel.constants;
            const call = (path, args) =>
                this.bridge.callOffsetI32(`native.exports.${path}`, args);
            const fd = call("socket", [K.afInet, K.sockStream, 0]);
            if (fd < 0) {
                const errno = this.lastErrno();
                throw new Error("elfldr probe socket failed"
                    + `: result=${fd} errno=${errno ?? "unavailable"}`);
            }
            let result;
            let errno = null;
            try {
                result = call("bind", [fd, this.sockaddr.address, 0x10]);
                if (result !== 0) errno = this.lastErrno();
            } finally {
                const closeResult = call("close", [fd]);
                if (closeResult !== 0)
                    throw new Error(`elfldr probe close(${fd}) failed: ${closeResult}`);
            }
            if (result === 0)
                return { present: false, port: PAYLOAD_PORT, errno: null };
            if (errno === EADDRINUSE)
                return { present: true, port: PAYLOAD_PORT, errno };
            throw new Error("elfldr probe bind failed"
                + `: result=${result} errno=${errno ?? "unavailable"}`);
        }

        async fetchPayload(url, artifact) {
            const expected = new URL(url, root.location.href);
            if (artifact && expected.origin !== root.location.origin)
                throw new Error("pinned payload URL is not same-origin");
            const response = await fetch(url, { cache: "no-store" });
            if (!response.ok)
                throw new Error(`payload fetch failed: HTTP ${response.status}`);
            if (artifact) {
                const received = new URL(response.url || expected.href,
                    root.location.href);
                if (received.href !== expected.href)
                    throw new Error("pinned payload fetch redirected");
            }
            const buffer = await response.arrayBuffer();
            const bytes = new Uint8Array(buffer);
            if (bytes.length < 4)
                throw new Error("payload is too small");
            if (bytes[0] !== 0x7f || bytes[1] !== 0x45
                || bytes[2] !== 0x4c || bytes[3] !== 0x46)
                throw new Error("payload does not start with the ELF signature");
            if (artifact) {
                if (bytes.byteLength !== artifact.size)
                    throw new Error(`payload size mismatch ${bytes.byteLength}/${artifact.size}`);
                if (!this.hash)
                    throw new Error("payload SHA-256 verifier is unavailable");
                const digest = await this.hash(buffer);
                if (digest !== artifact.sha256)
                    throw new Error(`payload SHA-256 mismatch: ${digest}`);
            }
            return bytes;
        }

        async send(action) {
            const descriptor = typeof action === "string"
                ? { artifact: { path: action } }
                : (action || UNIFIED_AUTOLOADER);
            const artifact = descriptor.artifact || {};
            const payloadUrl = artifact.path;
            if (typeof payloadUrl !== "string" || !payloadUrl)
                throw new Error("payload artifact path is unavailable");
            const pinned = Number.isSafeInteger(artifact.size)
                && typeof artifact.sha256 === "string" ? artifact : null;
            const bytes = await this.fetchPayload(payloadUrl, pinned);
            this.allocateBuffers();

            const K = this.profile.raw.kernel.constants;
            const call = (path, args) =>
                this.bridge.callOffsetI32(`native.exports.${path}`, args);

            const fd = call("socket", [K.afInet, K.sockStream, 0]);
            if (fd < 0)
                throw new Error(`payload socket creation failed: ${fd}`);

            let sent = 0;
            let failure = null;
            try {
                let result = call("setsockopt",
                    [fd, K.solSocket, K.soNosigpipe,
                        this.optionBuf.address, 4]);
                if (result !== 0)
                    throw new Error(`SO_NOSIGPIPE failed: ${result}`);

                result = call("setsockopt",
                    [fd, K.solSocket, K.soSndtimeo,
                        this.timeoutBuf.address, 0x10]);
                if (result !== 0)
                    throw new Error(`SO_SNDTIMEO failed: ${result}`);

                result = call("connect",
                    [fd, this.sockaddr.address, 0x10]);
                if (result !== 0)
                    throw new Error(`connect to 127.0.0.1:${PAYLOAD_PORT} failed: ${result}`);

                while (sent < bytes.length) {
                    const chunk = Math.min(SEND_BUFFER_SIZE, bytes.length - sent);
                    this.sendBuf.write(0, bytes.subarray(sent, sent + chunk));
                    let chunkSent = 0;
                    while (chunkSent < chunk) {
                        const written = call("write",
                            [fd, this.sendBuf.address + chunkSent,
                                chunk - chunkSent]);
                        if (written <= 0)
                            throw new Error(`write failed at byte ${sent + chunkSent}: ${written}`);
                        chunkSent += written;
                    }
                    sent += chunk;
                }
            } catch (error) {
                failure = error;
            }

            const closeResult = call("close", [fd]);
            if (closeResult !== 0) {
                const msg = `close(${fd}) failed: ${closeResult}`;
                if (failure) throw new Error(`${failure.message}; ${msg}`);
                if (sent < bytes.length) throw new Error(msg);
            }
            if (failure) throw failure;
            return { id: descriptor.id || "payload", bytes: sent,
                port: PAYLOAD_PORT };
        }
    }

    NS.PayloadSender = PayloadSender;
    NS.PayloadSettings = { load: loadSettings, resolve: resolveSettings,
        SETTINGS_KEY };
    NS.PostActions = Object.freeze({
        all() { return ACTIONS.slice(); },
        get(id) { return ACTIONS.find((action) => action.id === id) || null; },
        supportsFirmware(id, firmware) {
            const action = ACTIONS.find((entry) => entry.id === id) || null;
            return actionSupportsFirmware(action, firmware);
        },
        validate: validateActionRegistry
    });
    if (typeof module !== "undefined" && module.exports)
        module.exports = { PayloadSender,
            PayloadSettings: NS.PayloadSettings, PostActions: NS.PostActions,
            UNIFIED_AUTOLOADER, PAYLOAD_PORT, EADDRINUSE,
            validateActionRegistry };
})(typeof globalThis !== "undefined" ? globalThis : this);
