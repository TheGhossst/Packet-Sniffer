import { ValidationError } from './errors';

export type IPVersion = 4 | 6;

export interface IPRange {
    version: IPVersion;
    start: bigint;
    end: bigint;
}

export class NetworkUtils {
    /**
     * Convert IPv4 or IPv6 address to numeric representation
     */
    static ipToNumber(ip: string): { version: IPVersion; value: bigint } {
        if (this.isIPv4(ip)) {
            return {
                version: 4,
                value: this.ipv4ToNumber(ip)
            };
        } else if (this.isIPv6(ip)) {
            return {
                version: 6,
                value: this.ipv6ToNumber(ip)
            };
        }
        throw new ValidationError('ip', `Invalid IP address format: ${ip}`);
    }

    /**
     * Check if IP is within CIDR range
     */
    static isInRange(ip: string, cidr: string): boolean {
        const [network, bits] = cidr.split('/');
        const prefix = parseInt(bits);

        const ipNum = this.ipToNumber(ip);
        const networkNum = this.ipToNumber(network);

        if (ipNum.version !== networkNum.version) {
            return false;
        }

        const maxBits = ipNum.version === 4 ? 32 : 128;
        if (prefix < 0 || prefix > maxBits) {
            throw new ValidationError('cidr', `Invalid prefix length: ${prefix}`);
        }

        const shiftBits = BigInt(maxBits - prefix);
        const ipPrefix = ipNum.value >> shiftBits;
        const networkPrefix = networkNum.value >> shiftBits;

        return ipPrefix === networkPrefix;
    }

    /**
     * Parse CIDR notation to IP range
     */
    static parseCIDR(cidr: string): IPRange {
        const [network, bits] = cidr.split('/');
        const prefix = parseInt(bits);
        const networkNum = this.ipToNumber(network);
        const maxBits = networkNum.version === 4 ? 32 : 128;

        if (prefix < 0 || prefix > maxBits) {
            throw new ValidationError('cidr', `Invalid prefix length: ${prefix}`);
        }

        const shiftBits = BigInt(maxBits - prefix);
        const start = networkNum.value & (BigInt(-1) << shiftBits);
        const end = start | ((BigInt(1) << shiftBits) - BigInt(1));

        return {
            version: networkNum.version,
            start,
            end
        };
    }

    /**
     * Check if string is valid IPv4 address
     */
    static isIPv4(ip: string): boolean {
        const pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!pattern.test(ip)) return false;

        return ip.split('.').every(octet => {
            const num = parseInt(octet);
            return num >= 0 && num <= 255;
        });
    }

    /**
     * Check if string is valid IPv6 address
     */
    static isIPv6(ip: string): boolean {
        const pattern = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
        return pattern.test(this.expandIPv6(ip));
    }

    /**
     * Convert IPv4 address to number
     */
    private static ipv4ToNumber(ip: string): bigint {
        return BigInt(ip.split('.')
            .reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0);
    }

    /**
     * Convert IPv6 address to number
     */
    private static ipv6ToNumber(ip: string): bigint {
        const expanded = this.expandIPv6(ip);
        const parts = expanded.split(':');
        let result = BigInt(0);

        for (const part of parts) {
            result = (result << BigInt(16)) | BigInt(parseInt(part, 16));
        }

        return result;
    }

    /**
     * Expand shortened IPv6 address to full form
     */
    private static expandIPv6(ip: string): string {
        // Handle IPv4-mapped IPv6 addresses
        if (ip.includes('.')) {
            const lastColon = ip.lastIndexOf(':');
            const ipv4Part = ip.slice(lastColon + 1);
            if (this.isIPv4(ipv4Part)) {
                const ipv4Num = this.ipv4ToNumber(ipv4Part);
                const hex = ipv4Num.toString(16).padStart(8, '0');
                ip = `${ip.slice(0, lastColon)}:${hex.slice(0, 4)}:${hex.slice(4)}`;
            }
        }

        // Handle :: shorthand
        if (ip.includes('::')) {
            const parts = ip.split('::');
            const missing = 8 - (
                parts[0].split(':').length +
                parts[1].split(':').length
            );
            const expansion = ':'.repeat(missing).split(':').join('0:');
            ip = parts[0] + ':' + expansion + parts[1];
        }

        // Pad each part to 4 characters
        return ip.split(':')
            .map(part => part.padStart(4, '0'))
            .join(':');
    }
} 