(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const { U64, readU32LE, writeU32LE, readU64LE, writeU64LE } = NS;
    if (!U64) throw new Error("src/u64.js must be loaded before memory.js");

    class UserlandMemory {
        constructor(options) {
            if (!options || !options.carrier || !options.view
                || typeof options.aim !== "function")
                throw new TypeError("invalid arbitrary-memory handoff");
            this.carrier = options.carrier;
            this.view = options.view;
            this.aimPrimitive = options.aim;
            this.restorePrimitive = options.restore || null;
            this.originalVector = U64.from(options.originalVector || 0);
            this.current = null;
            this.released = false;
        }

        static assertAddress(address) {
            if (!Number.isSafeInteger(address) || address <= 0x100000000
                || address > 0xffffffffffff)
                throw new RangeError(`invalid user address: ${address}`);
        }

        aim(address) {
            if (this.released) throw new Error("memory primitive was released");
            UserlandMemory.assertAddress(address);
            this.aimPrimitive(this.carrier, address);
            this.current = address;
            return this.view;
        }

        read(address, length) {
            UserlandMemory.assertAddress(address);
            if (!Number.isInteger(length) || length < 0)
                throw new RangeError("invalid read length");
            const result = new Uint8Array(length);
            let done = 0;
            while (done < length) {
                const count = Math.min(this.view.length, length - done);
                const source = this.aim(address + done);
                for (let i = 0; i < count; ++i) result[done + i] = source[i];
                done += count;
            }
            return result;
        }

        write(address, source) {
            UserlandMemory.assertAddress(address);
            const bytes = source instanceof Uint8Array
                ? source : new Uint8Array(source);
            let done = 0;
            while (done < bytes.length) {
                const count = Math.min(this.view.length, bytes.length - done);
                const target = this.aim(address + done);
                for (let i = 0; i < count; ++i) target[i] = bytes[done + i];
                done += count;
            }
        }

        fill(address, value, length) {
            const block = new Uint8Array(Math.min(this.view.length, length));
            block.fill(value & 0xff);
            for (let done = 0; done < length; done += block.length)
                this.write(address + done, block.subarray(0,
                    Math.min(block.length, length - done)));
        }

        read8(address) { return this.read(address, 1)[0]; }
        read16(address) {
            const b = this.read(address, 2);
            return b[0] | (b[1] << 8);
        }
        read32(address) { return readU32LE(this.read(address, 4), 0); }
        read64(address) { return readU64LE(this.read(address, 8), 0); }

        write8(address, value) {
            this.write(address, new Uint8Array([value & 0xff]));
        }
        write16(address, value) {
            const b = new Uint8Array(2);
            b[0] = value & 0xff;
            b[1] = (value >>> 8) & 0xff;
            this.write(address, b);
        }
        write32(address, value) {
            const b = new Uint8Array(4);
            writeU32LE(b, 0, value);
            this.write(address, b);
        }
        write64(address, value) {
            const b = new Uint8Array(8);
            writeU64LE(b, 0, value);
            this.write(address, b);
        }

        writeCString(address, text, capacity) {
            const input = String(text);
            if (input.length + 1 > capacity)
                throw new RangeError("C string exceeds destination");
            const b = new Uint8Array(capacity);
            for (let i = 0; i < input.length; ++i) {
                const code = input.charCodeAt(i);
                if (code > 0x7f) throw new TypeError("only ASCII strings are supported");
                b[i] = code;
            }
            this.write(address, b);
        }

        park(address) { this.aim(address); }

        release() {
            if (this.released) return;
            if (this.restorePrimitive)
                this.restorePrimitive(this.carrier);
            this.current = null;
            this.released = true;
        }
    }

    class NativeBuffer {
        constructor(memory, address, size, label) {
            UserlandMemory.assertAddress(address);
            if (!Number.isInteger(size) || size <= 0)
                throw new RangeError("invalid native buffer size");
            this.memory = memory;
            this.address = address;
            this.size = size;
            this.label = label || "buffer";
        }

        check(offset, length) {
            if (!Number.isInteger(offset) || !Number.isInteger(length)
                || offset < 0 || length < 0 || offset + length > this.size)
                throw new RangeError(`${this.label}: out-of-bounds access`);
        }

        ptr(offset) {
            const n = offset || 0;
            this.check(n, 0);
            return this.address + n;
        }

        sub(offset, size, label) {
            this.check(offset, size);
            return new NativeBuffer(this.memory, this.address + offset, size,
                label || `${this.label}+0x${offset.toString(16)}`);
        }

        read(offset, length) {
            this.check(offset, length);
            return this.memory.read(this.address + offset, length);
        }
        write(offset, bytes) {
            const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
            this.check(offset, input.length);
            this.memory.write(this.address + offset, input);
        }
        fill(value) { this.memory.fill(this.address, value, this.size); }
        get8(offset) { this.check(offset, 1); return this.memory.read8(this.address + offset); }
        get16(offset) { this.check(offset, 2); return this.memory.read16(this.address + offset); }
        get32(offset) { this.check(offset, 4); return this.memory.read32(this.address + offset); }
        get64(offset) { this.check(offset, 8); return this.memory.read64(this.address + offset); }
        put8(offset, value) { this.check(offset, 1); this.memory.write8(this.address + offset, value); }
        put16(offset, value) { this.check(offset, 2); this.memory.write16(this.address + offset, value); }
        put32(offset, value) { this.check(offset, 4); this.memory.write32(this.address + offset, value); }
        put64(offset, value) { this.check(offset, 8); this.memory.write64(this.address + offset, value); }
        putCString(offset, text, capacity) {
            this.check(offset, capacity);
            this.memory.writeCString(this.address + offset, text, capacity);
        }
    }

    NS.UserlandMemory = UserlandMemory;
    NS.NativeBuffer = NativeBuffer;
    if (typeof module !== "undefined" && module.exports)
        module.exports = { UserlandMemory, NativeBuffer };
})(typeof globalThis !== "undefined" ? globalThis : this);
