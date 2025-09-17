// page/cache.js
import { Logger } from './utils.js';

const logger = new Logger('CACHE');
const CACHE_KEY = 'processedOrdersCache';
const CACHE_EXPIRATION_MS = 60 * 60 * 1000; // 1 hour

/**
 * Manages a cache of processed order IDs to prevent duplicate processing.
 * The cache is persisted in localStorage and automatically cleared every hour.
 */
class CacheService {
    constructor() {
        this.processedOrders = new Set();
        this._loadCache();
        this._scheduleCleanup();
    }

    /**
     * Loads the persisted cache from localStorage.
     */
    _loadCache() {
        try {
            const storedCache = localStorage.getItem(CACHE_KEY);
            if (storedCache) {
                const parsed = JSON.parse(storedCache);
                // Ensure the loaded data is an array before creating a Set
                if (Array.isArray(parsed)) {
                    this.processedOrders = new Set(parsed);
                    logger.info(`Loaded ${this.processedOrders.size} processed orders from cache.`);
                }
            }
        } catch (error) {
            logger.error('Failed to load cache from localStorage:', error.message);
            this.processedOrders = new Set();
        }
    }

    /**
     * Saves the current cache to localStorage.
     */
    _saveCache() {
        try {
            // Convert Set to Array for JSON serialization
            const arrayToStore = Array.from(this.processedOrders);
            localStorage.setItem(CACHE_KEY, JSON.stringify(arrayToStore));
        } catch (error) {
            logger.error('Failed to save cache to localStorage:', error.message);
        }
    }

    /**
     * Clears the cache both in memory and in localStorage.
     */
    _clearCache() {
        this.processedOrders.clear();
        localStorage.removeItem(CACHE_KEY);
        logger.info('Cache has been cleared.');
    }

    /**
     * Sets up a recurring timer to clear the cache every hour.
     */
    _scheduleCleanup() {
        setInterval(() => {
            this._clearCache();
        }, CACHE_EXPIRATION_MS);
    }

    /**
     * Adds an orderId to the cache of processed orders.
     * @param {string | number} orderId The ID of the order to add.
     */
    addProcessedOrder(orderId) {
        if (!orderId) return;
        this.processedOrders.add(String(orderId));
        this._saveCache();
        logger.log(`Added orderId ${orderId} to cache.`);
    }

    /**
     * Checks if an orderId has already been processed.
     * @param {string | number} orderId The ID of the order to check.
     * @returns {boolean} True if the order has been processed, false otherwise.
     */
    isOrderProcessed(orderId) {
        if (!orderId) return false;
        return this.processedOrders.has(String(orderId));
    }
}

// Export a singleton instance of the service
export const cacheService = new CacheService();
