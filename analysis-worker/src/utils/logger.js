const PacketFormatter = require('./packetFormatter');

class Logger {
    constructor(options = {}) {
        this.level = options.level || 'info';
        this.levels = {
            error: 0,
            warn: 1,
            info: 2,
            debug: 3
        };
        this.useColors = options.colors !== false;
    }

    format(level, message, meta = {}) {
        const timestamp = new Date().toISOString();
        let formattedMessage = message;

        if (meta.packet) {
            const formatted = PacketFormatter.formatPacket(meta.packet);
            formattedMessage = `\nPacket Analysis:\n${formatted.formatted}`;
            delete meta.packet;
        }

        if (meta.alerts) {
            formattedMessage += '\nAlerts:';
            meta.alerts.forEach(alert => {
                const formatted = PacketFormatter.formatAlert(alert);
                formattedMessage += `\n${formatted.formatted}`;
            });
            delete meta.alerts;
        }

        const metaStr = Object.keys(meta).length ? `\nMetadata: ${JSON.stringify(meta, null, 2)}` : '';
        
        return {
            timestamp,
            level,
            message: formattedMessage,
            meta: metaStr,
            formatted: `[${timestamp}] ${level.toUpperCase()}: ${formattedMessage}${metaStr}`
        };
    }

    log(level, message, meta = {}) {
        if (this.levels[this.level] >= this.levels[level]) {
            const formatted = this.format(level, message, meta);
            if (this.useColors) {
                console.log(PacketFormatter.colorize(formatted.formatted, level.toUpperCase()));
            } else {
                console.log(formatted.formatted);
            }
        }
    }

    error(message, meta) { this.log('error', message, meta); }
    warn(message, meta) { this.log('warn', message, meta); }
    info(message, meta) { this.log('info', message, meta); }
    debug(message, meta) { this.log('debug', message, meta); }
}

module.exports = Logger; 