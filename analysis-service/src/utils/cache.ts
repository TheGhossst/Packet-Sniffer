import { CacheError, ErrorCode } from './errors';
import { createHash } from 'crypto';
import { gzip, gunzip } from 'zlib';
import { promisify } from 'util';
import { logger } from './logger';

const gzipAsync = promisify(gzip);
const gunzipAsync = promisify(gunzip);

interface CacheEntry<T> {
    value: T | Buffer;
    timestamp: number;
    ttl: number;
    lastAccessed: number;
    accessCount: number;
    version?: string;
    compressed?: boolean;
}

interface CacheStats {
    hits: number;
    misses: number;
    evictions: number;
    size: number;
    hitRate: number;
    averageTtl: number;
    compressionRatio: number;
    stampedePrevented: number;
    persistentStorageHits: number;
}

interface CacheOptions {
    maxSize: number;
    defaultTtl: number;
    cleanupInterval: number;
    compressionThreshold?: number;
    persistentStorage?: boolean;
    stampedeProtection?: boolean;
    maxStaleAge?: number;
}

interface PersistentStorage {
    get(key: string): Promise<CacheEntry<any> | null>;
    set(key: string, entry: CacheEntry<any>): Promise<void>;
    delete(key: string): Promise<void>;
    clear(): Promise<void>;
}

type StampedePromise<T> = {
    promise: Promise<T>;
    timestamp: number;
};

export class AdvancedCache<T> {
    private cache: Map<string, CacheEntry<T>>;
    private readonly maxSize: number;
    private readonly defaultTtl: number;
    private readonly compressionThreshold: number;
    private readonly persistentStorage?: PersistentStorage;
    private readonly stampedeProtection: boolean;
    private readonly maxStaleAge: number;
    private inFlightRequests: Map<string, StampedePromise<T>> = new Map();
    private stats: {
        hits: number;
        misses: number;
        evictions: number;
        stampedePrevented: number;
        persistentStorageHits: number;
        bytesBeforeCompression: number;
        bytesAfterCompression: number;
    };

    constructor(options: CacheOptions) {
        this.cache = new Map();
        this.maxSize = options.maxSize;
        this.defaultTtl = options.defaultTtl;
        this.compressionThreshold = options.compressionThreshold || 1024;
        this.stampedeProtection = options.stampedeProtection ?? true;
        this.maxStaleAge = options.maxStaleAge || 60000; // 1 minute default stale age
        this.stats = {
            hits: 0,
            misses: 0,
            evictions: 0,
            stampedePrevented: 0,
            persistentStorageHits: 0,
            bytesBeforeCompression: 0,
            bytesAfterCompression: 0
        };

        if (options.persistentStorage) {
            // Initialize persistent storage (implementation would be injected)
            // this.persistentStorage = new PersistentStorageImplementation();
        }

        setInterval(() => this.cleanup(), options.cleanupInterval);
    }

    /**
     * Set a value in the cache with optional TTL and version
     */
    async set(
        key: string,
        value: T,
        ttl?: number,
        version?: string
    ): Promise<void> {
        try {
            if (this.cache.size >= this.maxSize) {
                this.evictLRU();
            }

            const entry = await this.prepareEntry(value, ttl, version);
            this.cache.set(key, entry);

            if (this.persistentStorage) {
                await this.persistentStorage.set(key, entry);
            }
        } catch (error) {
            throw new CacheError(
                error instanceof Error ? error.message : 'Unknown error',
                'set',
                { details: { key } }
            );
        }
    }

    /**
     * Get a value from the cache with optional stale-while-revalidate support
     */
    async get(
        key: string,
        fetchFn?: () => Promise<T>
    ): Promise<T | null> {
        try {
            // Check in-memory cache first
            const entry = this.cache.get(key);
            
            if (entry) {
                if (!this.isExpired(entry)) {
                    this.updateAccessStats(entry);
                    this.stats.hits++;
                    return this.deserializeValue(entry);
                }

                // Handle stale-while-revalidate
                if (fetchFn && Date.now() - entry.timestamp <= this.maxStaleAge) {
                    this.revalidate(key, fetchFn);
                    return this.deserializeValue(entry);
                }
            }

            // Check persistent storage if available
            if (!entry && this.persistentStorage) {
                const persistentEntry = await this.persistentStorage.get(key);
                if (persistentEntry && !this.isExpired(persistentEntry)) {
                    this.cache.set(key, persistentEntry);
                    this.stats.persistentStorageHits++;
                    return this.deserializeValue(persistentEntry);
                }
            }

            // Handle cache stampede
            if (fetchFn && this.stampedeProtection) {
                return this.getWithStampedeProtection(key, fetchFn);
            }

            this.stats.misses++;
            return null;
        } catch (error) {
            throw new CacheError(
                error instanceof Error ? error.message : 'Unknown error',
                'get',
                { details: { key } }
            );
        }
    }

    /**
     * Check if a key exists and is not expired
     */
    async has(key: string): Promise<boolean> {
        const entry = this.cache.get(key);
        if (entry && !this.isExpired(entry)) {
            return true;
        }

        if (this.persistentStorage) {
            const persistentEntry = await this.persistentStorage.get(key);
            return !!persistentEntry && !this.isExpired(persistentEntry);
        }

        return false;
    }

    /**
     * Delete a key from all cache tiers
     */
    async delete(key: string): Promise<boolean> {
        const memoryDeleted = this.cache.delete(key);
        
        if (this.persistentStorage) {
            await this.persistentStorage.delete(key);
        }

        return memoryDeleted;
    }

    /**
     * Clear all cache tiers
     */
    async clear(): Promise<void> {
        this.cache.clear();
        this.inFlightRequests.clear();
        
        if (this.persistentStorage) {
            await this.persistentStorage.clear();
        }

        this.resetStats();
    }

    /**
     * Get enhanced cache statistics
     */
    getStats(): CacheStats {
        const totalRequests = this.stats.hits + this.stats.misses;
        const hitRate = totalRequests > 0 ? this.stats.hits / totalRequests : 0;

        let totalTtl = 0;
        this.cache.forEach(entry => {
            totalTtl += entry.ttl;
        });

        const compressionRatio = this.stats.bytesAfterCompression > 0 ?
            this.stats.bytesBeforeCompression / this.stats.bytesAfterCompression : 1;

        return {
            ...this.stats,
            size: this.cache.size,
            hitRate,
            averageTtl: this.cache.size > 0 ? totalTtl / this.cache.size : 0,
            compressionRatio
        };
    }

    /**
     * Update TTL and version for a specific key
     */
    async updateMetadata(
        key: string,
        updates: { ttl?: number; version?: string }
    ): Promise<boolean> {
        const entry = this.cache.get(key);
        if (entry) {
            if (updates.ttl !== undefined) entry.ttl = updates.ttl;
            if (updates.version !== undefined) entry.version = updates.version;
            
            if (this.persistentStorage) {
                await this.persistentStorage.set(key, entry);
            }
            return true;
        }
        return false;
    }

    /**
     * Get keys ordered by access frequency
     */
    getHotKeys(limit: number = 10): Array<{ key: string; accessCount: number }> {
        return Array.from(this.cache.entries())
            .map(([key, entry]) => ({
                key,
                accessCount: entry.accessCount
            }))
            .sort((a, b) => b.accessCount - a.accessCount)
            .slice(0, limit);
    }

    private async getWithStampedeProtection(
        key: string,
        fetchFn: () => Promise<T>
    ): Promise<T | null> {
        const inFlight = this.inFlightRequests.get(key);
        
        if (inFlight && Date.now() - inFlight.timestamp < 5000) {
            this.stats.stampedePrevented++;
            return inFlight.promise;
        }

        const promise = fetchFn().then(async value => {
            await this.set(key, value);
            this.inFlightRequests.delete(key);
            return value;
        });

        this.inFlightRequests.set(key, {
            promise,
            timestamp: Date.now()
        });

        return promise;
    }

    private async prepareEntry(
        value: T,
        ttl?: number,
        version?: string
    ): Promise<CacheEntry<T>> {
        const serialized = JSON.stringify(value);
        let finalValue: T | Buffer = value;
        let compressed = false;

        if (serialized.length > this.compressionThreshold) {
            this.stats.bytesBeforeCompression += serialized.length;
            const compressedValue = await gzipAsync(Buffer.from(serialized));
            this.stats.bytesAfterCompression += compressedValue.length;
            finalValue = compressedValue;
            compressed = true;
        }

        return {
            value: finalValue,
            timestamp: Date.now(),
            ttl: ttl || this.defaultTtl,
            lastAccessed: Date.now(),
            accessCount: 0,
            version,
            compressed
        };
    }

    private async deserializeValue(entry: CacheEntry<T>): Promise<T> {
        if (entry.compressed && Buffer.isBuffer(entry.value)) {
            const decompressed = await gunzipAsync(entry.value);
            return JSON.parse(decompressed.toString());
        }
        return entry.value as T;
    }

    private isExpired(entry: CacheEntry<T>): boolean {
        return Date.now() - entry.timestamp > entry.ttl;
    }

    private updateAccessStats(entry: CacheEntry<T>): void {
        entry.lastAccessed = Date.now();
        entry.accessCount++;
    }

    private evictLRU(): void {
        let oldestAccess = Date.now();
        let keyToEvict: string | null = null;

        for (const [key, entry] of this.cache.entries()) {
            if (entry.lastAccessed < oldestAccess) {
                oldestAccess = entry.lastAccessed;
                keyToEvict = key;
            }
        }

        if (keyToEvict) {
            this.cache.delete(keyToEvict);
            this.stats.evictions++;
        }
    }

    private async cleanup(): Promise<void> {
        const now = Date.now();
        
        // Cleanup memory cache
        for (const [key, entry] of this.cache.entries()) {
            if (this.isExpired(entry)) {
                this.cache.delete(key);
            }
        }

        // Cleanup in-flight requests
        for (const [key, request] of this.inFlightRequests.entries()) {
            if (now - request.timestamp > 5000) {
                this.inFlightRequests.delete(key);
            }
        }
    }

    private resetStats(): void {
        this.stats = {
            hits: 0,
            misses: 0,
            evictions: 0,
            stampedePrevented: 0,
            persistentStorageHits: 0,
            bytesBeforeCompression: 0,
            bytesAfterCompression: 0
        };
    }

    private async revalidate(key: string, fetchFn: () => Promise<T>): Promise<void> {
        try {
            const value = await fetchFn();
            await this.set(key, value);
        } catch (error) {
            logger.warn('Cache revalidation failed:', {
                key,
                error: error instanceof Error ? error.message : String(error)
            });
        }
    }
} 