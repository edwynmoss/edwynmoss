/**
 * Advanced Network Security Monitor
 * Author: Edwyn Moss
 * Description: Real-time network monitoring and security analysis tool
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const net = require('net');
const os = require('os');
const crypto = require('crypto');
const dns = require('dns');
const url = require('url');
const EventEmitter = require('events');

class NetworkSecurityMonitor extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            monitorInterval: config.monitorInterval || 5000,
            logLevel: config.logLevel || 'info',
            alertThresholds: {
                connectionCount: config.connectionThreshold || 1000,
                packetRate: config.packetRate || 10000,
                errorRate: config.errorRate || 0.1,
                responseTime: config.responseTime || 5000
            },
            outputDir: config.outputDir || './logs',
            enableRealTimeAlerts: config.enableRealTimeAlerts !== false,
            monitoredPorts: config.monitoredPorts || [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3389, 5432, 3306],
            blacklistedIPs: config.blacklistedIPs || [],
            whitelistedIPs: config.whitelistedIPs || []
        };
        
        this.metrics = {
            connections: new Map(),
            packets: { sent: 0, received: 0, errors: 0 },
            alerts: [],
            performance: { avgResponseTime: 0, uptime: 0 },
            security: { 
                suspiciousConnections: [],
                portScans: [],
                bruteForceAttempts: [],
                ddosAttacks: []
            }
        };
        
        this.startTime = Date.now();
        this.isMonitoring = false;
        
        // Initialize logging
        this.initializeLogging();
        
        // Security patterns for detection
        this.securityPatterns = {
            portScan: {
                timeWindow: 60000, // 1 minute
                connectionThreshold: 20,
                portThreshold: 10
            },
            bruteForce: {
                timeWindow: 300000, // 5 minutes
                attemptThreshold: 50,
                failureRate: 0.8
            },
            ddos: {
                timeWindow: 10000, // 10 seconds
                connectionThreshold: 100,
                sourceThreshold: 5
            }
        };
    }
    
    initializeLogging() {
        if (!fs.existsSync(this.config.outputDir)) {
            fs.mkdirSync(this.config.outputDir, { recursive: true });
        }
        
        this.logFile = path.join(this.config.outputDir, `network_monitor_${new Date().toISOString().split('T')[0]}.log`);
        this.alertFile = path.join(this.config.outputDir, `security_alerts_${new Date().toISOString().split('T')[0]}.log`);
    }
    
    log(level, message, data = {}) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level,
            message,
            data,
            hostname: os.hostname(),
            pid: process.pid
        };
        
        const logLine = JSON.stringify(logEntry) + '\n';
        
        // Console output with colors
        const colors = {
            error: '\x1b[31m',
            warn: '\x1b[33m',
            info: '\x1b[36m',
            debug: '\x1b[32m',
            reset: '\x1b[0m'
        };
        
        console.log(`${colors[level] || colors.info}[${timestamp}] ${level.toUpperCase()}: ${message}${colors.reset}`);
        
        // File logging
        fs.appendFileSync(this.logFile, logLine);
        
        // Alert logging
        if (level === 'error' || level === 'warn') {
            fs.appendFileSync(this.alertFile, logLine);
        }
        
        this.emit('log', logEntry);
    }
    
    async startMonitoring() {
        if (this.isMonitoring) {
            this.log('warn', 'Monitoring already started');
            return;
        }
        
        this.isMonitoring = true;
        this.log('info', 'Starting network security monitoring', {
            config: this.config,
            hostname: os.hostname(),
            platform: os.platform(),
            arch: os.arch()
        });
        
        // Start various monitoring components
        this.startPortMonitoring();
        this.startConnectionMonitoring();
        this.startPerformanceMonitoring();
        this.startSecurityAnalysis();
        this.startHealthCheck();
        
        // Emit monitoring started event
        this.emit('monitoringStarted');
    }
    
    stopMonitoring() {
        if (!this.isMonitoring) {
            this.log('warn', 'Monitoring not started');
            return;
        }
        
        this.isMonitoring = false;
        this.log('info', 'Stopping network security monitoring');
        
        // Clear all intervals
        if (this.monitoringInterval) clearInterval(this.monitoringInterval);
        if (this.performanceInterval) clearInterval(this.performanceInterval);
        if (this.securityInterval) clearInterval(this.securityInterval);
        if (this.healthInterval) clearInterval(this.healthInterval);
        
        this.emit('monitoringStopped');
    }
    
    startPortMonitoring() {
        this.log('info', 'Starting port monitoring', { ports: this.config.monitoredPorts });
        
        const checkPorts = () => {
            this.config.monitoredPorts.forEach(port => {
                this.checkPortStatus('localhost', port);
            });
        };
        
        // Initial check
        checkPorts();
        
        // Schedule regular checks
        this.monitoringInterval = setInterval(checkPorts, this.config.monitorInterval);
    }
    
    checkPortStatus(host, port) {
        return new Promise((resolve) => {
            const startTime = Date.now();
            const socket = new net.Socket();
            
            socket.setTimeout(this.config.alertThresholds.responseTime);
            
            socket.on('connect', () => {
                const responseTime = Date.now() - startTime;
                
                this.updatePortMetrics(host, port, 'open', responseTime);
                
                if (responseTime > this.config.alertThresholds.responseTime) {
                    this.generateAlert('performance', 'High response time detected', {
                        host, port, responseTime
                    });
                }
                
                socket.destroy();
                resolve({ host, port, status: 'open', responseTime });
            });
            
            socket.on('timeout', () => {
                this.updatePortMetrics(host, port, 'timeout');
                socket.destroy();
                resolve({ host, port, status: 'timeout' });
            });
            
            socket.on('error', (err) => {
                this.updatePortMetrics(host, port, 'closed');
                resolve({ host, port, status: 'closed', error: err.message });
            });
            
            socket.connect(port, host);
        });
    }
    
    updatePortMetrics(host, port, status, responseTime = 0) {
        const key = `${host}:${port}`;
        
        if (!this.metrics.connections.has(key)) {
            this.metrics.connections.set(key, {
                host,
                port,
                status,
                responseTime,
                lastCheck: Date.now(),
                checkCount: 1,
                statusHistory: [status]
            });
        } else {
            const connection = this.metrics.connections.get(key);
            connection.status = status;
            connection.responseTime = responseTime;
            connection.lastCheck = Date.now();
            connection.checkCount++;
            connection.statusHistory.push(status);
            
            // Keep only last 100 status entries
            if (connection.statusHistory.length > 100) {
                connection.statusHistory = connection.statusHistory.slice(-100);
            }
        }
    }
    
    startConnectionMonitoring() {
        this.log('info', 'Starting connection monitoring');
        
        // Monitor active network connections
        setInterval(() => {
            this.analyzeNetworkConnections();
        }, this.config.monitorInterval);
    }
    
    analyzeNetworkConnections() {
        try {
            // Get network interfaces
            const interfaces = os.networkInterfaces();
            
            Object.keys(interfaces).forEach(interfaceName => {
                interfaces[interfaceName].forEach(iface => {
                    if (iface.family === 'IPv4' && !iface.internal) {
                        this.monitorInterface(interfaceName, iface);
                    }
                });
            });
            
        } catch (error) {
            this.log('error', 'Failed to analyze network connections', { error: error.message });
        }
    }
    
    monitorInterface(name, iface) {
        const interfaceKey = `${name}_${iface.address}`;
        
        // Store interface metrics
        if (!this.metrics.connections.has(interfaceKey)) {
            this.metrics.connections.set(interfaceKey, {
                name,
                address: iface.address,
                netmask: iface.netmask,
                mac: iface.mac,
                family: iface.family,
                internal: iface.internal,
                bytesReceived: 0,
                bytesSent: 0,
                packetsReceived: 0,
                packetsSent: 0,
                errors: 0,
                drops: 0
            });
        }
        
        // Emit interface data for real-time monitoring
        this.emit('interfaceData', { name, iface });
    }
    
    startPerformanceMonitoring() {
        this.log('info', 'Starting performance monitoring');
        
        this.performanceInterval = setInterval(() => {
            this.collectPerformanceMetrics();
        }, this.config.monitorInterval);
    }
    
    collectPerformanceMetrics() {
        const memUsage = process.memoryUsage();
        const cpuUsage = process.cpuUsage();
        const uptime = process.uptime();
        
        const performanceData = {
            memory: {
                rss: memUsage.rss,
                heapTotal: memUsage.heapTotal,
                heapUsed: memUsage.heapUsed,
                external: memUsage.external
            },
            cpu: {
                user: cpuUsage.user,
                system: cpuUsage.system
            },
            uptime: uptime,
            loadAverage: os.loadavg(),
            freeMemory: os.freemem(),
            totalMemory: os.totalmem()
        };
        
        this.metrics.performance = performanceData;
        
        // Check for performance alerts
        if (memUsage.heapUsed / memUsage.heapTotal > 0.9) {
            this.generateAlert('performance', 'High memory usage detected', {
                heapUsage: (memUsage.heapUsed / memUsage.heapTotal * 100).toFixed(2) + '%'
            });
        }
        
        this.emit('performanceData', performanceData);
    }
    
    startSecurityAnalysis() {
        this.log('info', 'Starting security analysis');
        
        this.securityInterval = setInterval(() => {
            this.detectPortScans();
            this.detectBruteForceAttempts();
            this.detectDDoSAttacks();
            this.analyzeConnectionPatterns();
        }, this.config.monitorInterval);
    }
    
    detectPortScans() {
        const now = Date.now();
        const timeWindow = this.securityPatterns.portScan.timeWindow;
        const connectionThreshold = this.securityPatterns.portScan.connectionThreshold;
        const portThreshold = this.securityPatterns.portScan.portThreshold;
        
        // Group connections by source IP in time window
        const recentConnections = new Map();
        
        this.metrics.connections.forEach((connection, key) => {
            if (connection.lastCheck && (now - connection.lastCheck) < timeWindow) {
                const sourceKey = connection.host || 'unknown';
                
                if (!recentConnections.has(sourceKey)) {
                    recentConnections.set(sourceKey, {
                        connectionCount: 0,
                        ports: new Set(),
                        connections: []
                    });
                }
                
                const source = recentConnections.get(sourceKey);
                source.connectionCount++;
                source.ports.add(connection.port);
                source.connections.push(connection);
            }
        });
        
        // Analyze for port scan patterns
        recentConnections.forEach((data, sourceIP) => {
            if (data.connectionCount > connectionThreshold && data.ports.size > portThreshold) {
                this.generateSecurityAlert('port_scan', 'Port scan detected', {
                    sourceIP,
                    connectionCount: data.connectionCount,
                    uniquePorts: data.ports.size,
                    timeWindow: timeWindow / 1000 + 's'
                });
            }
        });
    }
    
    detectBruteForceAttempts() {
        // This would analyze authentication logs for brute force patterns
        // For demonstration, we'll simulate detection logic
        
        const suspiciousPatterns = [
            { pattern: /failed.*login/i, weight: 1 },
            { pattern: /authentication.*failed/i, weight: 1 },
            { pattern: /invalid.*user/i, weight: 2 },
            { pattern: /password.*incorrect/i, weight: 1 }
        ];
        
        // In a real implementation, this would parse actual log files
        // For now, we'll emit a placeholder
        this.emit('bruteForceAnalysis', { 
            analyzed: true, 
            patterns: suspiciousPatterns.length 
        });
    }
    
    detectDDoSAttacks() {
        const now = Date.now();
        const timeWindow = this.securityPatterns.ddos.timeWindow;
        const connectionThreshold = this.securityPatterns.ddos.connectionThreshold;
        
        // Count recent connections
        let recentConnectionCount = 0;
        const sourceCounts = new Map();
        
        this.metrics.connections.forEach((connection) => {
            if (connection.lastCheck && (now - connection.lastCheck) < timeWindow) {
                recentConnectionCount++;
                
                const source = connection.host || 'unknown';
                sourceCounts.set(source, (sourceCounts.get(source) || 0) + 1);
            }
        });
        
        // Check for DDoS patterns
        if (recentConnectionCount > connectionThreshold) {
            const topSources = Array.from(sourceCounts.entries())
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5);
                
            this.generateSecurityAlert('ddos', 'Potential DDoS attack detected', {
                totalConnections: recentConnectionCount,
                timeWindow: timeWindow / 1000 + 's',
                topSources: topSources
            });
        }
    }
    
    analyzeConnectionPatterns() {
        // Analyze connection patterns for anomalies
        const patterns = {
            unusualPorts: [],
            suspiciousIPs: [],
            abnormalTraffic: []
        };
        
        this.metrics.connections.forEach((connection, key) => {
            // Check for connections to unusual ports
            if (connection.port && connection.port > 49152) { // Dynamic/private ports
                patterns.unusualPorts.push({
                    host: connection.host,
                    port: connection.port,
                    lastSeen: connection.lastCheck
                });
            }
            
            // Check against blacklisted IPs
            if (this.config.blacklistedIPs.includes(connection.host)) {
                patterns.suspiciousIPs.push({
                    ip: connection.host,
                    port: connection.port,
                    status: connection.status
                });
            }
        });
        
        // Generate alerts for suspicious patterns
        if (patterns.unusualPorts.length > 10) {
            this.generateSecurityAlert('unusual_ports', 'High number of connections to unusual ports', {
                count: patterns.unusualPorts.length,
                sample: patterns.unusualPorts.slice(0, 5)
            });
        }
        
        if (patterns.suspiciousIPs.length > 0) {
            this.generateSecurityAlert('blacklisted_ip', 'Connection from blacklisted IP detected', {
                count: patterns.suspiciousIPs.length,
                ips: patterns.suspiciousIPs
            });
        }
    }
    
    generateAlert(type, message, data = {}) {
        const alert = {
            id: crypto.randomUUID(),
            type,
            message,
            data,
            timestamp: new Date().toISOString(),
            severity: this.getAlertSeverity(type),
            hostname: os.hostname()
        };
        
        this.metrics.alerts.push(alert);
        this.log('warn', `Alert: ${message}`, data);
        
        // Keep only last 1000 alerts
        if (this.metrics.alerts.length > 1000) {
            this.metrics.alerts = this.metrics.alerts.slice(-1000);
        }
        
        this.emit('alert', alert);
        
        if (this.config.enableRealTimeAlerts) {
            this.sendRealTimeAlert(alert);
        }
    }
    
    generateSecurityAlert(type, message, data = {}) {
        const securityAlert = {
            id: crypto.randomUUID(),
            type: 'security',
            subtype: type,
            message,
            data,
            timestamp: new Date().toISOString(),
            severity: 'high',
            hostname: os.hostname(),
            requiresInvestigation: true
        };
        
        this.metrics.security[type] = this.metrics.security[type] || [];
        this.metrics.security[type].push(securityAlert);
        
        this.log('error', `Security Alert: ${message}`, data);
        
        this.emit('securityAlert', securityAlert);
        
        if (this.config.enableRealTimeAlerts) {
            this.sendRealTimeAlert(securityAlert);
        }
    }
    
    getAlertSeverity(type) {
        const severityMap = {
            performance: 'medium',
            security: 'high',
            port_scan: 'high',
            ddos: 'critical',
            brute_force: 'high',
            connection: 'low'
        };
        
        return severityMap[type] || 'medium';
    }
    
    sendRealTimeAlert(alert) {
        // In a real implementation, this would send alerts via:
        // - Email
        // - Slack/Teams webhooks
        // - SMS
        // - Push notifications
        // - SIEM systems
        
        console.log(`\n🚨 REAL-TIME ALERT 🚨`);
        console.log(`Severity: ${alert.severity.toUpperCase()}`);
        console.log(`Type: ${alert.type}`);
        console.log(`Message: ${alert.message}`);
        console.log(`Time: ${alert.timestamp}`);
        console.log(`Data: ${JSON.stringify(alert.data, null, 2)}\n`);
    }
    
    startHealthCheck() {
        this.log('info', 'Starting health monitoring');
        
        this.healthInterval = setInterval(() => {
            this.performHealthCheck();
        }, this.config.monitorInterval * 2); // Check health less frequently
    }
    
    async performHealthCheck() {
        const healthData = {
            timestamp: new Date().toISOString(),
            status: 'healthy',
            checks: {}
        };
        
        // Check DNS resolution
        try {
            await this.checkDNS('google.com');
            healthData.checks.dns = { status: 'ok', message: 'DNS resolution working' };
        } catch (error) {
            healthData.checks.dns = { status: 'error', message: error.message };
            healthData.status = 'degraded';
        }
        
        // Check internet connectivity
        try {
            await this.checkHTTP('https://www.google.com');
            healthData.checks.internet = { status: 'ok', message: 'Internet connectivity working' };
        } catch (error) {
            healthData.checks.internet = { status: 'error', message: error.message };
            healthData.status = 'degraded';
        }
        
        // Check system resources
        const memUsage = (process.memoryUsage().heapUsed / process.memoryUsage().heapTotal) * 100;
        if (memUsage > 90) {
            healthData.checks.memory = { status: 'warning', message: `High memory usage: ${memUsage.toFixed(1)}%` };
            healthData.status = 'degraded';
        } else {
            healthData.checks.memory = { status: 'ok', message: `Memory usage: ${memUsage.toFixed(1)}%` };
        }
        
        // Check monitoring status
        healthData.checks.monitoring = { 
            status: this.isMonitoring ? 'ok' : 'error', 
            message: this.isMonitoring ? 'Monitoring active' : 'Monitoring stopped' 
        };
        
        this.emit('healthCheck', healthData);
        
        if (healthData.status !== 'healthy') {
            this.generateAlert('health', 'System health degraded', healthData);
        }
    }
    
    checkDNS(hostname) {
        return new Promise((resolve, reject) => {
            dns.lookup(hostname, (err, address) => {
                if (err) reject(err);
                else resolve(address);
            });
        });
    }
    
    checkHTTP(url) {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            const request = https.get(url, (response) => {
                const responseTime = Date.now() - startTime;
                
                if (response.statusCode >= 200 && response.statusCode < 300) {
                    resolve({ statusCode: response.statusCode, responseTime });
                } else {
                    reject(new Error(`HTTP ${response.statusCode}`));
                }
            });
            
            request.on('error', reject);
            request.setTimeout(5000, () => {
                request.destroy();
                reject(new Error('Request timeout'));
            });
        });
    }
    
    getMetrics() {
        return {
            ...this.metrics,
            uptime: Date.now() - this.startTime,
            isMonitoring: this.isMonitoring,
            config: this.config
        };
    }
    
    generateReport() {
        const metrics = this.getMetrics();
        const report = {
            generated: new Date().toISOString(),
            hostname: os.hostname(),
            platform: `${os.platform()} ${os.arch()}`,
            nodeVersion: process.version,
            uptime: metrics.uptime,
            summary: {
                totalConnections: metrics.connections.size,
                totalAlerts: metrics.alerts.length,
                securityEvents: Object.values(metrics.security).flat().length,
                monitoringStatus: metrics.isMonitoring ? 'active' : 'stopped'
            },
            alerts: metrics.alerts.slice(-50), // Last 50 alerts
            security: metrics.security,
            performance: metrics.performance,
            connections: Array.from(metrics.connections.entries()).map(([key, data]) => ({
                key,
                ...data
            }))
        };
        
        const reportPath = path.join(this.config.outputDir, `network_report_${Date.now()}.json`);
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
        
        this.log('info', 'Report generated', { path: reportPath });
        
        return report;
    }
    
    async scanHost(host, ports = null) {
        const targetPorts = ports || this.config.monitoredPorts;
        const results = [];
        
        this.log('info', `Starting host scan: ${host}`, { ports: targetPorts });
        
        for (const port of targetPorts) {
            try {
                const result = await this.checkPortStatus(host, port);
                results.push(result);
                
                // Add delay to avoid overwhelming the target
                await new Promise(resolve => setTimeout(resolve, 100));
            } catch (error) {
                results.push({ host, port, status: 'error', error: error.message });
            }
        }
        
        this.log('info', `Host scan completed: ${host}`, { 
            total: results.length,
            open: results.filter(r => r.status === 'open').length
        });
        
        return results;
    }
    
    exportMetrics(format = 'json') {
        const metrics = this.getMetrics();
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        
        if (format === 'json') {
            const filename = path.join(this.config.outputDir, `metrics_${timestamp}.json`);
            fs.writeFileSync(filename, JSON.stringify(metrics, null, 2));
            return filename;
        } else if (format === 'csv') {
            const filename = path.join(this.config.outputDir, `alerts_${timestamp}.csv`);
            const csvHeaders = 'Timestamp,Type,Severity,Message,Data\n';
            const csvData = metrics.alerts.map(alert => 
                `${alert.timestamp},${alert.type},${alert.severity},"${alert.message}","${JSON.stringify(alert.data).replace(/"/g, '""')}"`
            ).join('\n');
            
            fs.writeFileSync(filename, csvHeaders + csvData);
            return filename;
        }
    }
}

// CLI functionality
if (require.main === module) {
    const args = process.argv.slice(2);
    const config = {};
    
    // Parse command line arguments
    for (let i = 0; i < args.length; i += 2) {
        const arg = args[i];
        const value = args[i + 1];
        
        switch (arg) {
            case '--interval':
                config.monitorInterval = parseInt(value) * 1000;
                break;
            case '--output':
                config.outputDir = value;
                break;
            case '--ports':
                config.monitoredPorts = value.split(',').map(p => parseInt(p.trim()));
                break;
            case '--log-level':
                config.logLevel = value;
                break;
        }
    }
    
    const monitor = new NetworkSecurityMonitor(config);
    
    // Set up event handlers
    monitor.on('alert', (alert) => {
        console.log(`🔔 Alert: ${alert.message}`);
    });
    
    monitor.on('securityAlert', (alert) => {
        console.log(`🚨 Security Alert: ${alert.message}`);
    });
    
    monitor.on('healthCheck', (health) => {
        if (health.status !== 'healthy') {
            console.log(`⚠️  Health Check: ${health.status}`);
        }
    });
    
    // Handle shutdown gracefully
    process.on('SIGINT', () => {
        console.log('\nShutting down network monitor...');
        monitor.stopMonitoring();
        
        // Generate final report
        const report = monitor.generateReport();
        console.log(`Final report saved: ${JSON.stringify(report.summary, null, 2)}`);
        
        process.exit(0);
    });
    
    // Start monitoring
    monitor.startMonitoring();
    
    console.log(`
Network Security Monitor v1.0 - Author: Edwyn Moss
====================================================
Monitoring started. Press Ctrl+C to stop.
Configuration: ${JSON.stringify(config, null, 2)}
    `);
}

module.exports = NetworkSecurityMonitor; 