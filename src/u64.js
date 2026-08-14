(function (root) {
    "use strict";

    const NS = root.Slopkit = root.Slopkit || {};
    const TWO32 = 0x100000000;

    /** Exact unsigned 64-bit value represented as two uint32 words. */
    class U64 {
        constructor(lo, hi) {
            this.lo = Number(lo) >>> 0;
            this.hi = Number(hi) >>> 0;
            Object.freeze(this);
        }

        static from(value) {
            if (value instanceof U64)
                return value;
            if (typeof value === "number") {
                if (!Number.isFinite(value) || Math.floor(value) !== value)
                    throw new TypeError("U64 requires an integer");
                if (value < 0) {
                    if (value < -0x80000000)
                        throw new RangeError("negative U64 number must fit int32");
                    return new U64(value, 0xffffffff);
                }
                if (value > Number.MAX_SAFE_INTEGER)
                    throw new RangeError("unsafe number; use a hex string or U64");
                return new U64(value % TWO32, Math.floor(value / TWO32));
            }
            if (typeof value === "string")
                return U64.fromHex(value);
            if (typeof value === "bigint") {
                const mask = 0xffffffffn;
                const normalized = BigInt.asUintN(64, value);
                return new U64(Number(normalized & mask),
                    Number((normalized >> 32n) & mask));
            }
            if (value && Number.isInteger(value.lo) && Number.isInteger(value.hi))
                return new U64(value.lo, value.hi);
            throw new TypeError("unsupported U64 value");
        }

        static fromHex(text) {
            let value = String(text).trim().toLowerCase();
            if (value.startsWith("0x")) value = value.slice(2);
            if (!value || value.length > 16 || !/^[0-9a-f]+$/.test(value))
                throw new TypeError(`invalid 64-bit hex value: ${text}`);
            value = value.padStart(16, "0");
            return new U64(parseInt(value.slice(8), 16),
                parseInt(value.slice(0, 8), 16));
        }

        static zero() { return new U64(0, 0); }
        static ones() { return new U64(0xffffffff, 0xffffffff); }

        add(other) {
            const rhs = U64.from(other);
            const low = this.lo + rhs.lo;
            const carry = low >= TWO32 ? 1 : 0;
            return new U64(low, this.hi + rhs.hi + carry);
        }

        add32(value) { return this.add(U64.from(value)); }

        sub(other) {
            const rhs = U64.from(other);
            const borrow = this.lo < rhs.lo ? 1 : 0;
            return new U64(this.lo - rhs.lo, this.hi - rhs.hi - borrow);
        }

        and(other) {
            const rhs = U64.from(other);
            return new U64(this.lo & rhs.lo, this.hi & rhs.hi);
        }

        or(other) {
            const rhs = U64.from(other);
            return new U64(this.lo | rhs.lo, this.hi | rhs.hi);
        }

        xor(other) {
            const rhs = U64.from(other);
            return new U64(this.lo ^ rhs.lo, this.hi ^ rhs.hi);
        }

        not() { return new U64(~this.lo, ~this.hi); }

        shru(bits) {
            const n = Number(bits);
            if (!Number.isInteger(n) || n < 0)
                throw new RangeError("invalid shift");
            if (n >= 64) return U64.zero();
            if (n === 0) return this;
            if (n >= 32) return new U64(this.hi >>> (n - 32), 0);
            return new U64((this.lo >>> n) | (this.hi << (32 - n)),
                this.hi >>> n);
        }

        shl(bits) {
            const n = Number(bits);
            if (!Number.isInteger(n) || n < 0)
                throw new RangeError("invalid shift");
            if (n >= 64) return U64.zero();
            if (n === 0) return this;
            if (n >= 32) return new U64(0, this.lo << (n - 32));
            return new U64(this.lo << n,
                (this.hi << n) | (this.lo >>> (32 - n)));
        }

        eq(other) {
            const rhs = U64.from(other);
            return this.lo === rhs.lo && this.hi === rhs.hi;
        }

        compare(other) {
            const rhs = U64.from(other);
            if (this.hi !== rhs.hi) return this.hi < rhs.hi ? -1 : 1;
            if (this.lo !== rhs.lo) return this.lo < rhs.lo ? -1 : 1;
            return 0;
        }

        isZero() { return this.lo === 0 && this.hi === 0; }
        isMinusOne() { return this.lo === 0xffffffff && this.hi === 0xffffffff; }
        isKernelPointer() {
            // Four-level x86-64 high-half pointers have bits 63..47 set.
            // Do not restrict valid kernel addresses to ffffffff`xxxxxxxx.
            return (this.hi >>> 15) === 0x1ffff && !this.isMinusOne();
        }
        isUserPointer() {
            return this.hi >= 0x8 && this.hi < 0x9 && this.lo !== 0;
        }

        toNumber() {
            if (this.hi > 0x1fffff)
                throw new RangeError(`${this.toHex()} is not exactly representable`);
            return this.hi * TWO32 + this.lo;
        }

        toPointerNumber() {
            if (this.hi > 0xffff)
                throw new RangeError(`${this.toHex()} is not a low-48 user pointer`);
            return this.hi * TWO32 + this.lo;
        }

        toInt32() { return this.lo | 0; }
        toUint32() { return this.lo; }
        toBigInt() { return (BigInt(this.hi) << 32n) | BigInt(this.lo); }
        toHex() {
            return `0x${this.hi.toString(16).padStart(8, "0")}`
                + this.lo.toString(16).padStart(8, "0");
        }
        toString() { return this.toHex(); }
    }

    function readU32LE(bytes, offset) {
        return (bytes[offset]
            | (bytes[offset + 1] << 8)
            | (bytes[offset + 2] << 16)
            | (bytes[offset + 3] << 24)) >>> 0;
    }

    function writeU32LE(bytes, offset, value) {
        const v = Number(value) >>> 0;
        bytes[offset] = v & 0xff;
        bytes[offset + 1] = (v >>> 8) & 0xff;
        bytes[offset + 2] = (v >>> 16) & 0xff;
        bytes[offset + 3] = (v >>> 24) & 0xff;
    }

    function readU64LE(bytes, offset) {
        return new U64(readU32LE(bytes, offset), readU32LE(bytes, offset + 4));
    }

    function writeU64LE(bytes, offset, value) {
        const v = U64.from(value);
        writeU32LE(bytes, offset, v.lo);
        writeU32LE(bytes, offset + 4, v.hi);
    }

    NS.U64 = U64;
    NS.readU32LE = readU32LE;
    NS.writeU32LE = writeU32LE;
    NS.readU64LE = readU64LE;
    NS.writeU64LE = writeU64LE;

    if (typeof module !== "undefined" && module.exports)
        module.exports = { U64, readU32LE, writeU32LE, readU64LE, writeU64LE };
})(typeof globalThis !== "undefined" ? globalThis : this);
