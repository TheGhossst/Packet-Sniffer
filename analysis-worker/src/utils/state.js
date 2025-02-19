class StateManager {
    constructor() {
        this.states = new Map();
    }

    get(key) {
        return this.states.get(key);
    }

    set(key, value) {
        this.states.set(key, value);
    }

    update(key, updater) {
        const currentValue = this.states.get(key);
        const newValue = updater(currentValue);
        this.states.set(key, newValue);
        return newValue;
    }

    cleanup(maxAge = 3600000) { // Default 1 hour
        const now = Date.now();
        for (const [key, value] of this.states.entries()) {
            if (value.timestamp && (now - value.timestamp) > maxAge) {
                this.states.delete(key);
            }
        }
    }
}

module.exports = StateManager; 