(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    if (!NS.I18n || !NS.Profile || !NS.NativeBridge || !NS.PoopsKernel)
        throw new Error("runtime dependencies were not loaded");

    const OFFSETS_URL = "offsets/offsets.json";
    const DIRTY_PREFIX = "slopkit:kernel-state:";
    const BOOT_GUARD_PREFIX = "slopkit:kernel-boot-guard:";
    const ARM_PREFIX = "slopkit:arm:";
    const P2JB_ETA_WARMUP_SECONDS = 30;
    const P2JB_ETA_WARMUP_PERCENT = 0.5;
    const RECOVERY_DISPOSITIONS = Object.freeze({
        SAFE_NORMAL_REBOOT: "safe-normal-reboot",
        DIRTY_COLD_POWER_CYCLE: "dirty-cold-power-cycle",
        SEALED: "sealed"
    });
    function finishAttempt(attemptId, result) {
        try { return NS.Attempts?.finish(attemptId, result) || null; }
        catch { return null; }
    }

    function encodeHex(bytes) {
        return Array.from(bytes, (value) =>
            value.toString(16).padStart(2, "0")).join("");
    }

    function storageGet(key) {
        try { return root.localStorage.getItem(key); } catch { return null; }
    }
    function storageSet(key, value) {
        try {
            root.localStorage.setItem(key, value);
            return root.localStorage.getItem(key) === value;
        } catch { return false; }
    }

    function copy(translator, key, values) {
        const translate = typeof translator === "function"
            ? translator : NS.I18n.t;
        return translate(key, values);
    }

    const Runtime = {
        active: null,

        formatDuration(seconds, roundUp, translator) {
            if (!Number.isFinite(seconds) || seconds < 0) return null;
            const total = Math.max(0, roundUp
                ? Math.ceil(seconds) : Math.floor(seconds));
            const hours = Math.floor(total / 3600);
            const minutes = Math.floor((total % 3600) / 60);
            const remainder = total % 60;
            if (hours > 0) return copy(translator, "time.hours", {
                hours,
                minutes: String(minutes).padStart(2, "0"),
                seconds: String(remainder).padStart(2, "0")
            });
            if (minutes > 0) return copy(translator, "time.minutes", {
                minutes,
                seconds: String(remainder).padStart(2, "0")
            });
            return copy(translator, "time.seconds", { seconds: remainder });
        },

        formatP2jbBurnStatus(percent, etaSeconds, detail, translator) {
            const boundedPercent = Number.isFinite(percent)
                ? Math.max(0, Math.min(100, percent)) : 0;
            const displayPercent = boundedPercent >= 100
                ? 100 : Math.floor(boundedPercent);
            const elapsedSeconds = Number(detail?.elapsedSeconds);
            const elapsed = this.formatDuration(elapsedSeconds, false,
                translator) || this.formatDuration(0, false, translator);
            if (boundedPercent >= 100)
                return copy(translator, "runtime.status.p2jbComplete", {
                    elapsed
                });
            const etaReady = elapsedSeconds >= P2JB_ETA_WARMUP_SECONDS
                && boundedPercent >= P2JB_ETA_WARMUP_PERCENT
                && Number.isFinite(etaSeconds) && etaSeconds >= 0;
            if (!etaReady)
                return copy(translator, "runtime.status.p2jbEstimating", {
                    percent: displayPercent, elapsed
                });
            const remaining = this.formatDuration(etaSeconds, true,
                translator);
            return copy(translator, "runtime.status.p2jbRemaining", {
                percent: displayPercent, elapsed, remaining
            });
        },

        dirtyKey(firmware) { return `${DIRTY_PREFIX}${firmware}`; },
        bootGuardKey(firmware) { return `${BOOT_GUARD_PREFIX}${firmware}`; },

        verifyStorage(storage, label) {
            if (!storage || typeof storage.getItem !== "function"
                    || typeof storage.setItem !== "function"
                    || typeof storage.removeItem !== "function")
                throw new Error(`${label} storage is unavailable`);
            const key = `slopkit:storage-probe:${label}:${Date.now()}`;
            const value = `${Math.random()}`;
            try {
                storage.setItem(key, value);
                if (storage.getItem(key) !== value)
                    throw new Error("readback mismatch");
                storage.removeItem(key);
                if (storage.getItem(key) !== null)
                    throw new Error("removal mismatch");
            } catch {
                try { storage.removeItem(key); } catch {}
                throw new Error(`${label} storage is unavailable`);
            }
            return true;
        },

        recoveryDisposition(session, dirty) {
            if (dirty && session?.kernel?.sealed !== true)
                return RECOVERY_DISPOSITIONS.DIRTY_COLD_POWER_CYCLE;
            return RECOVERY_DISPOSITIONS.SAFE_NORMAL_REBOOT;
        },

        isDirtyFailure(session, error, unexpectedLiveWorkers) {
            const preDirtyCleanupVerified
                = session?.kernelAttemptStarted === true
                && session?.kernel?.preDirtyCleanupVerified === true
                && error?.rollbackVerified === true;
            const startedWithoutVerifiedCleanup
                = session?.kernelAttemptStarted === true
                && session?.kernel?.sealed !== true
                && !preDirtyCleanupVerified;
            return session?.dirty === true
                || session?.kernel?.dirty === true
                || session?.kernel?.rebootRequired === true
                || error?.rollbackVerified === false
                || unexpectedLiveWorkers === true
                || startedWithoutVerifiedCleanup;
        },

        getKernelState(firmware) {
            const raw = storageGet(this.dirtyKey(firmware));
            if (!raw) return null;
            try { return JSON.parse(raw); } catch { return { state: "unknown", raw }; }
        },

        getBootGuard(firmware) {
            const raw = storageGet(this.bootGuardKey(firmware));
            if (!raw) return null;
            try { return JSON.parse(raw); }
            catch { return { state: "invalid", raw }; }
        },

        readBootIdentity(bridge, allocator) {
            // kern.boottime is a timeval.  Treat its exact bytes as an opaque
            // boot identity so this remains independent of timeval field
            // interpretation and clock formatting.
            try {
                const name = allocator.alloc(0x20, 8, "boot-id-name");
                const output = allocator.alloc(0x20, 8, "boot-id-value");
                const size = allocator.alloc(8, 8, "boot-id-size");
                name.putCString(0, "kern.boottime", 0x20);
                size.put64(0, 0x20);
                const result = bridge.callOffsetI32(
                    "native.exports.sysctlbyname", [
                        name.address, output.address, size.address, 0, 0
                    ]);
                if (result !== 0) return null;
                const length = size.get32(0) >>> 0;
                if (length < 8 || length > 0x20) return null;
                const bytes = output.read(0, length);
                let nonzero = false;
                for (let index = 0; index < bytes.length; ++index)
                    if (bytes[index] !== 0) { nonzero = true; break; }
                if (!nonzero) return null;
                return `boottime-v1:${encodeHex(bytes)}`;
            } catch {
                return null;
            }
        },

        requireBootIdentity(bootId) {
            if (bootId) return bootId;
            const error = new Error(
                "kern.boottime is unavailable; kernel start refused");
            error.rebootRequired = true;
            throw error;
        },

        verifyBootGuard(firmware, bootId) {
            if (!bootId) return false;
            const previous = this.getBootGuard(firmware);
            if (previous?.state === "kernel-attempt-started"
                    && previous.bootId === bootId) {
                const error = new Error(
                    "a kernel exploit already started during this boot");
                error.rebootRequired = true;
                throw error;
            }
            return true;
        },

        recordBootAttempt(firmware, bootId, attemptId, exploit) {
            if (!bootId) return false;
            const record = {
                version: 1,
                state: "kernel-attempt-started",
                firmware, bootId, attemptId, exploit,
                rebootRequired: true,
                recoveryDisposition:
                    RECOVERY_DISPOSITIONS.DIRTY_COLD_POWER_CYCLE,
                updated: new Date().toISOString()
            };
            if (!storageSet(this.bootGuardKey(firmware), JSON.stringify(record)))
                throw new Error("persistent boot-attempt guard is unavailable");
            return true;
        },

        kernelDiagnostics(kernel) {
            if (!kernel || typeof kernel.diagnosticsSnapshot !== "function")
                return undefined;
            try { return kernel.diagnosticsSnapshot(); }
            catch { return undefined; }
        },

        sealKernel(session, handoff, kernel, postError, updateStage) {
            if (kernel?.resourcePolicy?.requiresSeal !== true) return null;
            const sealName = String(handoff.exploit || "kernel").toUpperCase();
            if (updateStage) updateStage("runtime.stage.finishing");
            try {
                session.kernelSeal = kernel.seal();
                if (handoff.exploit === "p2jb")
                    session.p2jbSeal = session.kernelSeal;
                try { handoff.setDiagnosticsQuiet?.(false); } catch {}
                return session.kernelSeal;
            } catch (sealError) {
                if (postError) {
                    const combined = new Error(`${postError.message};`
                        + ` ${sealName} seal failed: ${sealError.message}`);
                    combined.rebootRequired = true;
                    combined.rollbackVerified = false;
                    throw combined;
                }
                throw sealError;
            }
        },

        shouldSealBeforePayloadDelivery(kernel) {
            return kernel?.resourcePolicy?.sealBeforePayloadDelivery === true;
        },

        assertPayloadDeliverySafe(kernel) {
            if (this.shouldSealBeforePayloadDelivery(kernel)) {
                const payloadDeliverySafe
                    = kernel?.resourcePolicy?.payloadDeliverySafe === true
                    || kernel?.resourcePolicy?.closeSafe === true;
                const safe = kernel?.sealed === true
                    && kernel?.sealResult
                    && kernel?.dirty !== true
                    && kernel?.rebootRequired !== true
                    && payloadDeliverySafe;
                if (!safe)
                    throw new Error(
                        "payload delivery refused before verified kernel"
                        + ` transport seal sealed=${kernel?.sealed === true}`
                        + ` closeSafe=${kernel?.resourcePolicy?.closeSafe === true}`
                        + ` payloadDeliverySafe=${payloadDeliverySafe}`
                        + ` dirty=${kernel?.dirty === true}`
                        + ` rebootRequired=${kernel?.rebootRequired === true}`);
            }
            return true;
        },

        canOfferManualPayload(handoff) {
            return typeof NS.PayloadSender === "function"
                && typeof NS.PostActions?.all === "function"
                && NS.PostActions.all().length > 0
                && typeof handoff?.showPostExploitActions === "function";
        },

        postActionPlan(settings, availableActions) {
            const preferences = settings || {};
            const effectivePreferences = Object.assign({}, preferences);
            if (typeof preferences.autoLaunchAutoloader !== "boolean") {
                effectivePreferences.autoLaunchAutoloader
                    = preferences.autoLaunchPayloadManager === true
                        || preferences.autoSendPayload === true;
            }
            const actions = Array.isArray(availableActions)
                ? availableActions.slice().sort((left, right) =>
                    (left.order || 0) - (right.order || 0)) : [];
            const autoLaunchAutoloader
                = effectivePreferences.autoLaunchAutoloader === true;
            const requestedAction = actions.find((action) =>
                action.requested === true) || null;
            const autoloader = actions.find((action) =>
                action.id === "unified-autoloader") || null;
            const visible = actions.slice();
            const automatic = actions.filter((action) =>
                action.requested === true
                    || (typeof action.autoSetting === "string"
                        && effectivePreferences[action.autoSetting] === true));
            return {
                autoLaunchAutoloader,
                requestedAction,
                autoloader,
                visible,
                automatic
            };
        },

        async runAutomaticActions(plan, launch, onFailure) {
            const results = [];
            for (const action of plan?.automatic || []) {
                try {
                    results.push({ action, payload: await launch(action) });
                } catch (error) {
                    onFailure?.(action, error);
                    results.push({ action, error });
                    if (action.optional !== true) throw error;
                }
            }
            return results;
        },

        postActionModels(session, actions, launch) {
            const terminalActionId = session?.terminalActionId;
            if (terminalActionId
                    && session?.actionResults?.[terminalActionId]?.state
                        === "sent")
                return [];
            return (actions || []).map((action) => {
                const result = session?.actionResults?.[action.id]
                    || { state: action.artifact?.path
                        ? "ready" : "unavailable" };
                const blockedByTerminal = session?.terminalActionId
                    && session.terminalActionId !== action.id
                    && result.state !== "sending" && result.state !== "sent";
                const resourcesReleased = session?.allocatorReleased === true
                    || session?.memoryReleased === true;
                const state = blockedByTerminal || (resourcesReleased
                    && result.state !== "sent")
                    ? "unavailable" : result.state;
                return Object.assign({}, action, {
                    state,
                    bytes: result.payload?.bytes,
                    launch: state === "ready" || state === "failed"
                        ? () => launch(action) : null
                });
            });
        },

        async deliverPayload(session, settings, updateStage, markProgress) {
            if (!session?.kernel || !session.profile || !session.handoff)
                throw new Error("payload delivery session is unavailable");
            if (typeof NS.PayloadSender !== "function")
                throw new Error("payload sender is unavailable");

            const action = settings?.action
                || NS.PostActions?.get?.("unified-autoloader")
                || (settings?.payloadPath ? {
                    id: "unified-autoloader",
                    artifact: { path: settings.payloadPath },
                    terminal: true,
                    stageKey: "runtime.stage.startingAutoloader",
                    progressPrefix: "PAYLOAD"
                } : null);
            if (!action) throw new Error("payload action is unavailable");
            const actionId = action.id;
            if (typeof actionId !== "string" || !actionId)
                throw new Error("payload action identity is unavailable");
            const registeredAction = NS.PostActions?.get?.(actionId);
            const firmwareUnsupported = registeredAction
                ? !NS.PostActions.supportsFirmware(
                    actionId, session.handoff.firmware)
                : Array.isArray(action.firmwares)
                    && !action.firmwares.includes(session.handoff.firmware);
            if (firmwareUnsupported) {
                if (!session.actionResults)
                    session.actionResults = Object.create(null);
                session.actionResults[actionId] = { state: "unavailable" };
                session.renderActions?.();
                throw new Error(`${actionId} is unavailable on firmware `
                    + `${session.handoff.firmware}`);
            }
            if (!action.artifact?.path) {
                if (!session.actionResults)
                    session.actionResults = Object.create(null);
                session.actionResults[actionId] = { state: "unavailable" };
                session.renderActions?.();
                throw new Error(`${actionId} artifact is unavailable`);
            }
            if (!session.actionResults)
                session.actionResults = Object.create(null);
            if (!session.actionPromises)
                session.actionPromises = Object.create(null);
            if (session.actionResults[actionId]?.state === "sent")
                return session.actionResults[actionId].payload;
            if (session.actionPromises[actionId])
                return session.actionPromises[actionId];
            if ((session.terminalActionId
                    && session.terminalActionId !== actionId)
                    || session.allocatorReleased === true
                    || session.memoryReleased === true) {
                session.renderActions?.();
                throw new Error("payload action is unavailable after a terminal action");
            }
            this.assertPayloadDeliverySafe(session.kernel);
            if (action.terminal === true)
                session.terminalActionId = actionId;
            const prefix = action.progressPrefix || "PAYLOAD";
            const requested = prefix === "REQUESTED-ACTION";
            const startTag = requested
                ? "REQUESTED-ACTION-SEND-START" : "PAYLOAD-SEND-START";
            const sentTag = requested
                ? "REQUESTED-ACTION-SENT" : "PAYLOAD-SENT";
            const failedTag = requested
                ? "REQUESTED-ACTION-FAILED" : "FAILED-PAYLOAD";
            const predecessor = session.actionQueueTail || Promise.resolve();
            session.actionResults[actionId] = { state: "sending" };
            const task = Promise.resolve(predecessor).catch(() => undefined)
                .then(async () => {
                try {
                    session.actionResults[actionId] = { state: "sending" };
                    session.renderActions?.();
                    markProgress?.(startTag, actionId);
                    try {
                        NS.Attempts?.reach(session.handoff.armToken, "action");
                    } catch {}
                    // Unified Autoloader can terminate the WebKit entry app as
                    // soon as elfldr receives its final bytes. Persist the
                    // terminal handoff boundary before beginning that send.
                    if (action.terminal === true) {
                    }
                    session.handoff.showStatus?.("", "run");
                    updateStage?.(action.stageKey
                        || "runtime.stage.startingAutoloader");
                    const sender = session.payloadSender
                        || new NS.PayloadSender(session.kernel, session.profile);
                    session.payloadSender = sender;
                    const payload = await sender.send(action);
                    session.actionResults[actionId] = { state: "sent", payload };
                    markProgress?.(sentTag, `${actionId} ${payload.bytes} bytes`);
                    if (action.terminal === true) {
                        this.setKernelRecord(session.handoff.firmware,
                            "payload-sent", {
                            mode: session.handoff.mode,
                            attemptId: session.handoff.armToken,
                            rebootRequired:
                                session.kernel.rebootRequired === true,
                            payloadBytes: payload.bytes
                        });
                    }
                    updateStage?.("runtime.stage.finishing");
                    return payload;
                } catch (error) {
                    session.actionResults[actionId] = { state: "failed", error };
                    if (action.terminal === true
                            && session.terminalActionId === actionId)
                        session.terminalActionId = null;
                    markProgress?.(failedTag, actionId);
                    throw error;
                } finally {
                    session.renderActions?.();
                }
            });
            session.actionPromises[actionId] = task;
            // A rejected optional action must not poison the session queue.
            // Every later ELF starts only after its predecessor has settled.
            session.actionQueueTail = task.then(
                () => undefined, () => undefined
            );
            session.renderActions?.();
            try {
                return await task;
            } finally {
                if (session.actionPromises[actionId] === task)
                    delete session.actionPromises[actionId];
            }
        },

        profileBinding(profile) {
            const qualification = profile?.qualificationRecord?.();
            const binding = {
                exploit: profile?.exploit,
                profileRevision: qualification?.profileRevision,
                engineRevision: qualification?.engineRevision,
                runtimeRevision: qualification?.runtimeRevision
            };
            if (![binding.exploit, binding.profileRevision,
                binding.engineRevision, binding.runtimeRevision].every(
                (value) => typeof value === "string" && value.length > 0))
                throw new Error("runtime profile revision binding is incomplete");
            return binding;
        },

        recordMatchesProfile(record, handoff, profile, mode) {
            if (!record || !handoff || !profile) return false;
            const binding = this.profileBinding(profile);
            return record.firmware === handoff.firmware
                && record.mode === mode
                && record.exploit === handoff.exploit
                && binding.exploit === handoff.exploit
                && record.profileRevision === binding.profileRevision
                && record.engineRevision === binding.engineRevision
                && record.runtimeRevision === binding.runtimeRevision;
        },

        consumeArmToken(handoff) {
            const token = handoff?.armToken;
            if (!token) throw new Error("kernel mode was not manually armed");
            const key = `${ARM_PREFIX}${token}`;
            const record = this.readArmToken(token);
            if (!this.recordMatchesProfile(record, handoff, handoff.profile,
                handoff.mode))
                throw new Error("kernel arm token is absent or bound to another runtime profile");
            root.sessionStorage.removeItem(key);
            if (root.sessionStorage.getItem(key) !== null)
                throw new Error("kernel arm token could not be consumed");
            return true;
        },

        readArmToken(token) {
            if (!token) return null;
            try {
                return JSON.parse(root.sessionStorage.getItem(
                    `${ARM_PREFIX}${token}`) || "null");
            } catch { return null; }
        },

        resolveRendererTransport(handoff) {
            if (!handoff || handoff.mode !== "elf-loader" || !handoff.armToken)
                throw new Error("full mode requires authenticated elf-loader renderer transport");
            const record = this.readArmToken(handoff.armToken);
            const profile = handoff.profile;
            if (!profile || profile.firmware !== handoff.firmware
                || profile.mode !== "elf-loader"
                || profile.exploit !== handoff.exploit
                || typeof profile.offset !== "function")
                throw new Error("full renderer transport profile is invalid");
            if (!this.recordMatchesProfile(record, handoff, profile,
                "full-chain"))
                throw new Error("full renderer transport arm token is profile-mismatched");
            NS.Profile.validateExploitProfile(profile.raw, handoff.firmware,
                profile.metadata, handoff.exploit);
            const reboundProfile = new NS.Profile.FirmwareProfile(
                handoff.firmware, "full", profile.raw, profile.metadata,
                handoff.exploit);
            this.profileBinding(reboundProfile);

            // Rebind the launcher token only after the renderer work completes.
            const key = `${ARM_PREFIX}${handoff.armToken}`;
            try {
                record.mode = "full";
                root.sessionStorage.setItem(key, JSON.stringify(record));
                const reboundRecord = this.readArmToken(handoff.armToken);
                if (!this.recordMatchesProfile(reboundRecord, handoff,
                    reboundProfile, "full"))
                    throw new Error("arm token readback mismatch");
            } catch {
                try { root.sessionStorage.removeItem(key); } catch {}
                throw new Error("full renderer transport arm token rebound failed");
            }

            handoff.profile = reboundProfile;
            handoff.mode = "full";
        },

        verifyRendererWarmupToken(handoff) {
            if (handoff.mode !== "elf-loader" && handoff.mode !== "full")
                return null;
            const record = this.readArmToken(handoff.armToken);
            const warmup = record?.rendererWarmup;
            const valid = this.recordMatchesProfile(record, handoff,
                handoff.profile, handoff.mode)
                && warmup?.version === 1
                && warmup.method === "unarmed-precritical-placement-pairs-v1"
                && warmup.historyRead === false
                && warmup.historyReadIntercepts === 1
                && warmup.reportIntercepts === 1
                && warmup.released === true
                && warmup.placementPairs === 4
                && handoff.rendererPlacementPairs === 4;
            if (!valid) {
                const error = new Error(
                    "renderer warmup token does not prove the four-pair precritical prime");
                error.rebootRequired = true;
                throw error;
            }
        },

        verifyRuntimeExtension(handoff) {
            if (handoff.mode !== "elf-loader" && handoff.mode !== "full")
                return null;
            const extension = handoff.runtimeExtension;
            if (extension?.version !== 1 || extension.installed !== true
                || extension.postLoadCarrierProbe !== true) {
                const error = new Error(
                    "elf-loader runtime extension was not loaded and carrier-attested");
                error.rebootRequired = true;
                throw error;
            }
        },

        verifyLauncherAttempt(handoff) {
            const record = this.getKernelState(handoff.firmware);
            const valid = record
                && record.state === "renderer-attempt-claimed"
                && this.recordMatchesProfile(record, handoff,
                    handoff.profile, handoff.mode)
                && record.attemptId === handoff.armToken
                && record.rebootRequired === true;
            if (!valid) {
                const error = new Error(
                    "launcher attempt latch is absent or does not match this renderer handoff");
                error.rebootRequired = true;
                throw error;
            }
        },

        compareSignature(memory, address, expected, name) {
            const actual = encodeHex(memory.read(address, expected.length / 2));
            if (actual !== expected.toLowerCase())
                throw new Error(`${name} live signature mismatch: ${actual}`);
        },

        verifyLiveProfile(memory, profile, webkitBase, kernelBase, libcBase) {
            const slopkitAttested =
                typeof profile.isSlopkitAttested === "function"
                && profile.isSlopkitAttested() === true;
            if (!slopkitAttested
                && (typeof profile.isXomCode !== "function"
                    || !profile.isXomCode()))
                throw new Error("profile does not declare execute-only code");
            const validBase = (base) => Number.isSafeInteger(base)
                && base >= 0x800000000 && base < 0x900000000
                && (base & 0x3fff) === 0;
            if (!validBase(webkitBase) || !validBase(kernelBase)
                || webkitBase === kernelBase)
                throw new Error("live module bases are invalid");
            if (slopkitAttested && (!validBase(libcBase)
                || libcBase === webkitBase || libcBase === kernelBase))
                throw new Error("live-attested libc base is invalid");
            if (!slopkitAttested && libcBase !== undefined
                && libcBase !== null)
                throw new Error("exact profiles cannot accept a prevalidated libc base");

            const webkitTextSize = typeof profile.webkitCodeLimit === "function"
                ? profile.webkitCodeLimit()
                : profile.offset("webkit.textSize");
            const gadgets = profile.raw.webkit.gadgets;
            for (const [name, value] of Object.entries(gadgets)) {
                const rva = NS.Profile.parseOffset(value,
                    `webkit.gadgets.${name}`);
                if (rva >= webkitTextSize)
                    throw new Error(`WebKit gadget ${name} is outside XOM text`);
            }
            const nativeTextSize = profile.offset("native.textSize");
            for (const name of ["captureEntry", "setcontextEntry",
                "naturalTrampoline"]) {
                if (profile.offset(`native.context.${name}`) >= nativeTextSize)
                    throw new Error(`${name} is outside libkernel XOM text`);
            }
            const exports = profile.raw.native.exports;
            for (const name of Object.keys(exports)) {
                if (profile.offset(`native.exports.${name}`) >= nativeTextSize)
                    throw new Error(`native export ${name} is outside XOM text`);
            }
            const syscallStubs = profile.raw.native.syscallStubs;
            for (const name of Object.keys(syscallStubs)) {
                if (profile.offset(`native.syscallStubs.${name}`) >= nativeTextSize)
                    throw new Error(`native syscall stub ${name} is outside XOM text`);
            }
            for (const [kind, base] of [["webkit", webkitBase],
                ["native", kernelBase]]) {
                const anchors = profile.value(`${kind}.readableAnchors`);
                for (let index = 0; index < anchors.length; ++index) {
                    const anchor = anchors[index];
                    const address = base + NS.Profile.parseOffset(anchor.rva,
                        `${kind}.readableAnchors[${index}].rva`);
                    this.compareSignature(memory, address, anchor.bytes,
                        `${kind} readable anchor ${index}`);
                }
            }

            if (slopkitAttested) {
                const anchors = profile.value("libc.readableAnchors");
                for (let index = 0; index < anchors.length; ++index) {
                    const anchor = anchors[index];
                    const address = libcBase + NS.Profile.parseOffset(anchor.rva,
                        `libc.readableAnchors[${index}].rva`);
                    this.compareSignature(memory, address, anchor.bytes,
                        `libc readable anchor ${index}`);
                }
                for (const [name, base] of [["kernel", kernelBase],
                    ["libc", libcBase]]) {
                    const binding = profile.value(
                        `slopkitAttestation.${name}Import`);
                    const slot = NS.Profile.parseOffset(binding.slot,
                        `slopkitAttestation.${name}Import.slot`);
                    const exported = NS.Profile.parseOffset(binding.export,
                        `slopkitAttestation.${name}Import.export`);
                    const address = webkitBase + slot;
                    const expectedAddress = base + exported;
                    const moduleSize = name === "kernel"
                        ? profile.value("verified.libkernelWebSize")
                        : profile.offset("loader.libcTextSize");
                    if ((slot & 7) !== 0 || slot < webkitTextSize
                        || slot >= 0x10000000
                        || !Number.isSafeInteger(moduleSize)
                        || exported >= moduleSize
                        || address < 0x800000000 || address + 8 > 0x900000000
                        || expectedAddress < 0x800000000
                        || expectedAddress >= 0x900000000)
                        throw new Error(`${name} live-attested import is outside its module envelope`);
                    const first = memory.read64(address);
                    const second = memory.read64(address);
                    const expected = NS.U64.from(expectedAddress);
                    if (!first.eq(second) || !first.eq(expected)
                        || !first.isUserPointer())
                        throw new Error(`${name} live-attested import mismatch`);
                }
                return true;
            }

            const importNames = ["getpid", "close", "error"];
            for (const name of importNames) {
                const actual = memory.read64(webkitBase
                    + profile.offset(`webkit.imports.${name}.slot`));
                const expected = NS.U64.from(kernelBase
                    + profile.offset(`webkit.imports.${name}.export`));
                if (!actual.eq(expected))
                    throw new Error(`${name} live import mismatch: ${actual.toHex()}`);
            }
            return true;
        },

        setKernelRecord(firmware, state, extra, requirePersistence) {
            const details = extra || {};
            const previous = this.getKernelState(firmware);
            const sameAttempt = previous && (!details.attemptId
                || previous.attemptId === details.attemptId);
            const context = {};
            if (sameAttempt) {
                for (const key of ["exploit", "buildId", "profileRevision",
                    "engineRevision", "runtimeRevision", "runtimeDigest",
                    "qualificationStatus"]) {
                    if (previous[key] !== undefined)
                        context[key] = previous[key];
                }
            }
            const record = Object.assign(context, { state, firmware,
                updated: new Date().toISOString() }, details);
            const stored = storageSet(this.dirtyKey(firmware), JSON.stringify(record));
            if (!stored && requirePersistence !== false)
                throw new Error("persistent kernel-attempt storage is unavailable");
        },

        finish(handoff, headlineKey, detailKey, cls, values) {
            const translator = handoff.translate;
            const tone = cls || "ok";
            try { handoff.catState("ok"); } catch {}
            try {
                handoff.setCaption(copy(translator, "runtime.caption", {
                    firmware: handoff.firmware
                }));
            } catch {}
            try {
                handoff.setStageBanner?.(
                    copy(translator, headlineKey
                        || "runtime.stage.complete", values),
                    tone + (headlineKey ? "" : " complete"));
            } catch {}
            try {
                handoff.showStatus(detailKey
                    ? copy(translator, detailKey, values) : "", tone);
            } catch {}
        },

        fail(handoff, error, rebootRequired, recoveryDisposition) {
            const translator = handoff.translate;
            try { handoff.catState("bad"); } catch {}
            try {
                handoff.setCaption(copy(translator, "runtime.caption", {
                    firmware: handoff.firmware
                }));
            } catch {}
            try {
                handoff.setStageBanner?.(
                    copy(translator, recoveryDisposition
                        === RECOVERY_DISPOSITIONS.DIRTY_COLD_POWER_CYCLE
                        ? "runtime.stage.powerOff"
                        : "runtime.stage.stopped"), "bad");
            } catch {}
            const statusText = recoveryDisposition
                    === RECOVERY_DISPOSITIONS.DIRTY_COLD_POWER_CYCLE
                ? copy(translator, "runtime.status.coldPower")
                : rebootRequired
                    ? copy(translator, "runtime.status.reboot") : "";
            try { handoff.showStatus(statusText, "bad"); } catch {}
        },

        releaseKernelAllocator(session) {
            if (!session?.allocator || session.allocatorReleased) return false;
            const liveWorkers = session.kernel?.pool
                ? session.kernel.pool.liveWorkerCount() : 0;
            if (liveWorkers !== 0)
                throw new Error(`native arena release blocked by ${liveWorkers} live workers`);
            session.allocator.release();
            session.allocatorReleased = true;
            return true;
        },

        releaseCompletedResources(session) {
            if (!session?.kernel?.resourcePolicy?.retainAllocator)
                this.releaseKernelAllocator(session);
            if (!session?.kernel?.resourcePolicy?.retainMemory
                    && !session.memoryReleased) {
                session.memory?.release();
                session.memoryReleased = true;
            }
        },

        releaseAfterTerminalAction(session, action) {
            if (action?.terminal !== true) return false;
            session.terminalActionId = action.id;
            this.releaseCompletedResources(session);
            return true;
        },

        async bootstrap(handoff) {
            if (this.active) throw new Error("a slopkit runtime is already active");
            if (handoff?.mode !== "elf-loader")
                throw new Error("full-chain handoff is invalid");
            if (!["poops", "lapse", "p2jb"].includes(handoff.exploit))
                throw new Error("runtime exploit selection is invalid");
            this.verifyStorage(root.localStorage, "local");
            this.verifyStorage(root.sessionStorage, "session");
            const attemptId = handoff.armToken;
            const session = { handoff, dirty: false, kernel: null,
                memory: null, bridge: null, profile: null, allocator: null,
                allocatorReleased: false, memoryReleased: false,
                kernelAttemptStarted: false, bootId: null,
                bootGuarded: false, payloadSender: null,
                actionResults: Object.create(null),
                actionPromises: Object.create(null),
                actionQueueTail: Promise.resolve(), renderActions: null,
                actionNotice: null, terminalActionId: null,
                requestedAction: null,
                manualPayloadAvailable: false,
                reachedStages: new Set(["renderer"]) };
            this.active = session;
            const translator = handoff.translate;
            function updateStage(key, cls) {
                try {
                    if (handoff.setStageBanner)
                        handoff.setStageBanner(copy(translator, key), cls || "");
                }
                catch {}
            }
            function updateStatus(key, values, cls) {
                try {
                    if (handoff.showStatus)
                        handoff.showStatus(key ? copy(translator, key, values) : "",
                            cls || "run");
                }
                catch {}
            }
            const markProgress = (tag, extra) => {
                if (tag === "KERNEL-RW-RETURNED")
                    session.reachedStages.add("kernel");
                else if (/(?:-SEALED|-QUARANTINED)$/.test(String(tag)))
                    session.reachedStages.add("seal");
                else if (tag === "ELFLDR-READY")
                    session.reachedStages.add("loader");
                else if (tag === "PAYLOAD-SENT"
                        || tag === "REQUESTED-ACTION-SENT")
                    session.reachedStages.add("action");
                try { handoff.mark?.(tag, extra); } catch {}
            };
            try {
                updateStage("runtime.stage.preparing");
                updateStatus(null);
                let profile = handoff.profile;
                if (profile) {
                    if (profile.firmware !== handoff.firmware
                        || profile.mode !== handoff.mode
                        || profile.exploit !== handoff.exploit
                        || typeof profile.offset !== "function"
                        || typeof profile.qualification !== "function")
                        throw new Error("preloaded profile does not match runtime handoff");
                } else {
                    profile = await NS.Profile.loadForExploit(OFFSETS_URL,
                        handoff.firmware, handoff.mode, handoff.exploit);
                    handoff.profile = profile;
                }
                this.resolveRendererTransport(handoff);
                if (handoff.mode !== "full")
                    throw new Error("full-chain renderer transport was not authenticated");
                this.verifyRendererWarmupToken(handoff);
                this.verifyRuntimeExtension(handoff);
                this.verifyLauncherAttempt(handoff);
                const armRecord = this.readArmToken(handoff.armToken);
                if (armRecord?.requestedAction && !NS.PendingActions)
                    throw new Error("requested action validator is unavailable");
                session.requestedAction = NS.PendingActions
                    ?.actionFromArmRecord(armRecord, handoff.firmware) || null;
                this.consumeArmToken(handoff);
                this.setKernelRecord(handoff.firmware,
                    "renderer-handoff-verified", {
                        mode: handoff.mode,
                        attemptId: handoff.armToken,
                        rebootRequired: true
                    });
                profile = handoff.profile;
                session.profile = profile;
                const memory = new NS.UserlandMemory({ carrier: handoff.carrier,
                    view: handoff.rwView, aim: handoff.aimCarrier,
                    restore: handoff.restoreCarrier,
                    originalVector: handoff.originalVector });
                session.memory = memory;
                this.verifyLiveProfile(memory, profile, handoff.webkitBase,
                    handoff.kernelBase, handoff.libcBase);

                const bridge = new NS.NativeBridge({ memory, profile,
                    webkitBase: handoff.webkitBase, kernelBase: handoff.kernelBase,
                    arenaView: handoff.arenaView, arenaBase: handoff.arenaBase,
                    collatorAddress: handoff.collatorAddress,
                    originalCollator: handoff.originalCollator,
                    compare: handoff.compare });
                session.bridge = bridge;
                const pid = bridge.verify();
                this.setKernelRecord(handoff.firmware, "armed", {
                    mode: handoff.mode, pid, attemptId,
                    rebootRequired: true });
                const allocator = new NS.NativeAllocator(bridge, memory,
                    { regionSize: 0x400000 });
                session.allocator = allocator;
                session.bootId = this.requireBootIdentity(
                    this.readBootIdentity(bridge, allocator));
                session.bootGuarded = this.verifyBootGuard(
                    handoff.firmware, session.bootId);
                const startKernelAttempt = () => {
                    if (session.kernelAttemptStarted) return;
                    this.recordBootAttempt(handoff.firmware, session.bootId,
                        attemptId, handoff.exploit);
                    this.setKernelRecord(handoff.firmware,
                        "kernel-attempt-started", {
                            mode: handoff.mode, attemptId,
                            bootId: session.bootId,
                            bootGuarded: session.bootGuarded,
                            exploit: handoff.exploit,
                            rebootRequired: true,
                            recoveryDisposition:
                                RECOVERY_DISPOSITIONS.DIRTY_COLD_POWER_CYCLE
                        });
                    session.kernelAttemptStarted = true;
                    markProgress?.("KERNEL-ATTEMPT-START");
                };
                const markDirty = (reason) => {
                    // P2JB has a substantial read-only preflight.  Persist its
                    // once-per-boot kernel guard at the exact setuid boundary,
                    // while the other engines retain their entry-time guard.
                    if (handoff.exploit === "p2jb") startKernelAttempt();
                    this.setKernelRecord(handoff.firmware, "dirty", {
                        mode: handoff.mode, reason, attemptId,
                        bootId: session.bootId,
                        rebootRequired: true });
                    session.dirty = true;
                    if (handoff.exploit === "p2jb") {
                        updateStage("runtime.stage.runningP2jb");
                        updateStatus("runtime.status.p2jbInitial");
                    }
                };
                let kernel;
                if (handoff.exploit === "lapse") {
                    kernel = new NS.LapseKernel({ bridge, allocator,
                        memory, profile,
                        webkitBase: handoff.webkitBase,
                        kernelBase: handoff.kernelBase,
                        markDirty,
                        markProgress
                    });
                    session.kernel = kernel;
                    updateStage("runtime.stage.runningLapse");
                } else if (handoff.exploit === "p2jb") {
                    let lastBurnUiUpdate = 0;
                    const kernelOpts = { bridge, allocator, memory,
                        profile, webkitBase: handoff.webkitBase,
                        kernelBase: handoff.kernelBase,
                        markDirty, markProgress,
                        burnWorkers: handoff.p2jbBurnWorkers,
                        onBurnProgress(percent, etaSeconds, detail) {
                            const now = Date.now();
                            if (percent < 100
                                && now - lastBurnUiUpdate < 30000) return;
                            lastBurnUiUpdate = now;
                            try {
                                handoff.showStatus(Runtime.formatP2jbBurnStatus(
                                    percent, etaSeconds, detail, translator),
                                "run");
                            } catch {}
                        }
                    };
                    if (!NS.P2jbKernel)
                        throw new Error("dedicated P2JB engine is unavailable");
                    kernel = new NS.P2jbKernel(kernelOpts);
                    session.kernel = kernel;
                    updateStage("runtime.stage.preparingP2jb");
                    updateStatus("runtime.status.p2jbChecking");
                } else {
                    kernel = new NS.PoopsKernel({ bridge, allocator, memory,
                        profile, webkitBase: handoff.webkitBase,
                        kernelBase: handoff.kernelBase,
                        triggerFamily: "netcontrol", markDirty, markProgress });
                    session.kernel = kernel;
                    updateStage("runtime.stage.runningPoops");
                    updateStatus("runtime.status.poops");
                }
                if (handoff.exploit !== "p2jb") startKernelAttempt();
                try { handoff.setDiagnosticsQuiet?.(true); } catch {}
                await kernel.run();
                if (kernel?.resourcePolicy?.requiresSeal !== true) {
                    try { handoff.setDiagnosticsQuiet?.(false); } catch {}
                }
                if (!session.kernelAttemptStarted)
                    throw new Error("kernel engine returned before its dirty boundary");
                if (markProgress)
                    markProgress("KERNEL-RW-RETURNED", handoff.exploit);

                this.setKernelRecord(handoff.firmware, "kernel-ready", {
                    mode: handoff.mode, attemptId,
                    bootId: session.bootId,
                    diagnostics: this.kernelDiagnostics(kernel),
                    rebootRequired: kernel.rebootRequired === true });
                updateStage("runtime.stage.finishing");
                updateStatus(null);

                let postError = null;
                let kernelSealAttempted = false;
                try {
                const rooter = new NS.RootEscalator(kernel, profile);
                this.setKernelRecord(handoff.firmware,
                    "root-transaction-armed", {
                        mode: handoff.mode, attemptId,
                        rebootRequired: true
                    });
                const rootContext = rooter.patch();
                if (markProgress) markProgress("ROOT-PATCH-DONE");
                session.root = rootContext;
                const rootWriteCount = rooter.patchJournal.length;
                this.setKernelRecord(handoff.firmware, "rooted", {
                    mode: handoff.mode, attemptId,
                    rebootRequired: kernel.rebootRequired === true,
                    rootWrites: rootWriteCount });

                const sysentDiscovery = rooter.findNativeProcesses();
                const distinctTarget = sysentDiscovery.candidates.find(
                    (candidate) => candidate.distinct);
                const switcher = distinctTarget
                    ? new NS.SysentSwitcher(kernel, profile,
                        rootContext.curproc, distinctTarget.process)
                    : { run(callback) { return callback(); } };
                const gpu = new NS.GpuPatcher(kernel, rootContext,
                    switcher);
                switcher.run(() => {
                    gpu.setup();
                    gpu.patch();
                });
                if (markProgress) markProgress("GPU-PATCH-DONE");
                session.gpu = gpu;

                updateStage("runtime.stage.preparingElfldr");
                const prevalidatedLibcBase =
                    profile.isSlopkitAttested?.() === true
                    ? handoff.libcBase : undefined;
                const loader = new NS.ElfLoader(kernel, rootContext,
                    switcher, { libcBase: prevalidatedLibcBase });
                const preparedLoader = await loader.prepare();
                session.loaderPrepared = preparedLoader;
                if (markProgress) markProgress("ELFLDR-PREPARED");

                // ElfLoader has its own held pipe/socket transport. A
                // transient exploit transport must be sealed or quarantined
                // before the loader thread or any post action can execute.
                if (this.shouldSealBeforePayloadDelivery(kernel)) {
                    kernelSealAttempted = true;
                    this.sealKernel(session, handoff, kernel, null,
                        updateStage);
                    // Keep diagnostics quiet throughout the destructive phase.
                }

                updateStage("runtime.stage.startingElfldr");
                session.loader = await loader.start(preparedLoader, () => {
                    if (markProgress) markProgress("ELFLDR-STARTED");
                });
                if (markProgress) markProgress("ELFLDR-READY");

                } catch (error) {
                    postError = error;
                }

                if (!kernelSealAttempted) {
                    kernelSealAttempted = true;
                    this.sealKernel(session, handoff, kernel, postError,
                        updateStage);
                }
                if (postError) throw postError;

                // This is the exploit completion boundary. Persist and flush
                // it before a post action can fail, suspend, or replace the
                // browser process. Post-action results never rewrite it.
                this.setKernelRecord(handoff.firmware, "complete", {
                    mode: handoff.mode, attemptId,
                    bootId: session.bootId,
                    diagnostics: this.kernelDiagnostics(kernel),
                    rebootRequired: false,
                    recoveryDisposition: RECOVERY_DISPOSITIONS.SEALED });
                finishAttempt(attemptId, { outcome: "success",
                    terminalStage: "elfldr-ready", rebootRequired: false,
                    recoveryDisposition: RECOVERY_DISPOSITIONS.SEALED,
                    stages: Array.from(session.reachedStages) });
                markProgress?.("RUNTIME-COMPLETE");
                this.finish(handoff);

                const payloadSettings = NS.PayloadSettings
                    ? NS.PayloadSettings.resolve() : {
                        autoLaunchAutoloader: false
                    };
                const registeredActions = typeof NS.PostActions?.all === "function"
                    ? NS.PostActions.all().filter((action) =>
                        NS.PostActions.supportsFirmware(
                            action.id, handoff.firmware)) : [];
                const allActions = session.requestedAction
                    ? [session.requestedAction].concat(registeredActions)
                    : registeredActions;
                const actionPlan = this.postActionPlan(
                    payloadSettings, allActions);
                const autoloaderAction = actionPlan.autoloader;
                const actions = actionPlan.visible;
                const manualPayloadAvailable = this.canOfferManualPayload(handoff);
                session.manualPayloadAvailable = manualPayloadAvailable;
                let runAction;
                const renderActions = () => {
                    if (!manualPayloadAvailable) return;
                    const models = this.postActionModels(
                        session, actions, runAction);
                    handoff.showPostExploitActions?.({
                        actions: models,
                        autoloader: models.find((action) =>
                            action.id === "unified-autoloader") || null,
                        notice: session.actionNotice
                    });
                };
                session.renderActions = renderActions;
                runAction = async (action) => {
                    session.actionNotice = null;
                    let payload;
                    try {
                        const delivery = this.deliverPayload(session,
                            { action }, updateStage, markProgress);
                        renderActions();
                        payload = await delivery;
                        const values = {
                            action: copy(translator, action.titleKey)
                        };
                        session.actionNotice = {
                            headlineKey: action.sentKey
                                || "runtime.payload.sent",
                            detailKey: action.sentStatusKey
                                || "runtime.payload.sentStatus",
                            headlineValues: values,
                            detailValues: values,
                            cls: "ok"
                        };
                        this.finish(handoff,
                            session.actionNotice.headlineKey,
                            session.actionNotice.detailKey,
                            session.actionNotice.cls, values);
                        if (action.terminal === true) {
                            try { this.releaseAfterTerminalAction(session, action); }
                            catch (cleanupError) {
                                markProgress?.("PAYLOAD-CLEANUP-WARNING");
                            }
                        }
                        return payload;
                    } catch (error) {
                        const result = session.actionResults[action.id];
                        const unavailable = result?.state === "unavailable";
                        const headlineKey = unavailable
                            ? action.unavailableKey
                                || "runtime.payload.unavailable"
                            : action.failedKey || "runtime.payload.failed";
                        const detailKey = !unavailable
                                && action.failedStatusKey !== headlineKey
                            ? action.failedStatusKey || null : null;
                        const values = {
                            action: copy(translator, action.titleKey)
                        };
                        session.actionNotice = {
                            headlineKey,
                            detailKey,
                            headlineValues: values,
                            detailValues: values,
                            cls: "bad"
                        };
                        this.finish(handoff, headlineKey, detailKey, "bad",
                            values);
                        throw error;
                    } finally {
                        renderActions();
                    }
                };

                if (manualPayloadAvailable) {
                    renderActions();
                    markProgress?.("PAYLOAD-MANUAL-READY");
                }

                try {
                    await this.runAutomaticActions(actionPlan, runAction,
                        (action) => {
                            if (action.optional !== true)
                                markProgress?.("FAILED-PAYLOAD-ACTION", action.id);
                        });
                } catch {
                    // The exploit is already complete. runAction retained the
                    // action-specific failure state and manual retry surface.
                }

                if (!manualPayloadAvailable
                        && session.actionResults[autoloaderAction?.id]?.state
                            !== "sent") {
                    try { this.releaseCompletedResources(session); } catch {}
                }
                return session;
            } catch (error) {
                const liveWorkers = session.kernel?.pool
                    ? session.kernel.pool.liveWorkerCount() : 0;
                const expectedLiveWorkers = session.kernel?.resourcePolicy
                    ?.expectedParkedWorkers || 0;
                const unexpectedLiveWorkers = liveWorkers !== expectedLiveWorkers;
                const dirty = this.isDirtyFailure(
                    session, error, unexpectedLiveWorkers);
                const reboot = dirty || session.kernelAttemptStarted
                    || error.rebootRequired === true;
                const disposition = this.recoveryDisposition(session, dirty);
                const unsafeDirty = disposition
                    === RECOVERY_DISPOSITIONS.DIRTY_COLD_POWER_CYCLE;
                error.recoveryDisposition = disposition;
                if (session.kernel?.resourcePolicy?.requiresSeal === true
                        && !unsafeDirty) {
                    if (handoff.exploit === "p2jb" && markProgress) {
                        markProgress("P2JB-FAILURE", String(error.message)
                            .slice(0, 512));
                    }
                }
                if (!unsafeDirty) {
                    try { handoff.setDiagnosticsQuiet?.(false); } catch {}
                }
                if (unsafeDirty) {
                    this.setKernelRecord(handoff.firmware, "failed-dirty", {
                        mode: handoff.mode, attemptId,
                        bootId: session.bootId,
                        diagnostics: this.kernelDiagnostics(session.kernel),
                        rebootRequired: true, error: error.message,
                        stage: session.kernel?.stage || "unknown",
                        recoveryDisposition: disposition }, false);
                } else {
                    this.setKernelRecord(handoff.firmware,
                        "failed-stable", { mode: handoff.mode,
                            attemptId, rebootRequired: reboot,
                            bootId: session.bootId,
                            diagnostics: this.kernelDiagnostics(session.kernel),
                            error: error.message,
                            stage: session.kernel?.stage || "pre-kernel",
                            recoveryDisposition: disposition }, false);
                    let arenaSafe = !session.allocator;
                    if (!session.kernelAttemptStarted
                            || !session.kernel?.resourcePolicy?.retainAllocator) {
                        try {
                            this.releaseKernelAllocator(session);
                            arenaSafe = true;
                        } catch {}
                    }
                    if (arenaSafe) {
                        if (!session.kernelAttemptStarted
                                || !session.kernel?.resourcePolicy?.retainMemory) {
                            try { session.memory?.release(); } catch {}
                        }
                    }
                }
                finishAttempt(attemptId, { outcome: "failure",
                    terminalStage: session.kernel?.stage || "runtime",
                    rebootRequired: reboot,
                    recoveryDisposition: disposition,
                    stages: Array.from(session.reachedStages) });
                if (!unsafeDirty) {
                }
                this.fail(handoff, error, reboot, disposition);
                throw error;
            }
        }
    };

    NS.Runtime = Runtime;
    NS.RecoveryDispositions = RECOVERY_DISPOSITIONS;
    if (typeof module !== "undefined" && module.exports)
        module.exports = { Runtime, RECOVERY_DISPOSITIONS };
})(typeof globalThis !== "undefined" ? globalThis : this);
