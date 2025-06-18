<?php
/**
 * Advanced Web Security Crawler
 * Author: Edwyn Moss
 * Description: Web application security assessment tool
 */

class WebSecurityCrawler {
    private $baseUrl;
    private $visitedUrls = [];
    private $vulnerabilities = [];
    private $headers = [];
    private $cookies = [];
    
    public function __construct($url) {
        $this->baseUrl = rtrim($url, '/');
        $this->headers = [
            'User-Agent' => 'SecurityCrawler/1.0 (Security Assessment Tool)',
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language' => 'en-US,en;q=0.5',
            'Accept-Encoding' => 'gzip, deflate',
            'Connection' => 'keep-alive'
        ];
    }
    
    /**
     * Initialize CURL with security headers
     */
    private function initCurl($url) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_USERAGENT => $this->headers['User-Agent'],
            CURLOPT_HTTPHEADER => $this->formatHeaders(),
            CURLOPT_COOKIEJAR => 'cookies.txt',
            CURLOPT_COOKIEFILE => 'cookies.txt',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HEADER => true,
            CURLOPT_HEADERFUNCTION => [$this, 'parseHeaders']
        ]);
        return $ch;
    }
    
    /**
     * Format headers for CURL
     */
    private function formatHeaders() {
        $formatted = [];
        foreach ($this->headers as $key => $value) {
            $formatted[] = "$key: $value";
        }
        return $formatted;
    }
    
    /**
     * Parse response headers for security analysis
     */
    private function parseHeaders($ch, $header) {
        $header = trim($header);
        if (strpos($header, ':') !== false) {
            list($key, $value) = explode(':', $header, 2);
            $this->headers[trim($key)] = trim($value);
        }
        return strlen($header);
    }
    
    /**
     * Crawl website and extract URLs
     */
    public function crawlSite($startUrl = null, $depth = 2) {
        $url = $startUrl ?: $this->baseUrl;
        
        if ($depth <= 0 || in_array($url, $this->visitedUrls)) {
            return;
        }
        
        echo "[*] Crawling: $url\n";
        $this->visitedUrls[] = $url;
        
        $ch = $this->initCurl($url);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($response === false || $httpCode >= 400) {
            echo "[-] Failed to crawl: $url (HTTP $httpCode)\n";
            return;
        }
        
        // Security checks on current page
        $this->performSecurityChecks($url, $response);
        
        // Extract and crawl additional URLs
        $urls = $this->extractUrls($response);
        foreach ($urls as $newUrl) {
            if ($this->isInternalUrl($newUrl)) {
                $this->crawlSite($newUrl, $depth - 1);
            }
        }
    }
    
    /**
     * Extract URLs from HTML content
     */
    private function extractUrls($html) {
        $urls = [];
        
        // Extract href attributes
        preg_match_all('/<a[^>]+href=["\']([^"\']+)["\'][^>]*>/i', $html, $matches);
        foreach ($matches[1] as $url) {
            $urls[] = $this->normalizeUrl($url);
        }
        
        // Extract form actions
        preg_match_all('/<form[^>]+action=["\']([^"\']+)["\'][^>]*>/i', $html, $matches);
        foreach ($matches[1] as $url) {
            $urls[] = $this->normalizeUrl($url);
        }
        
        return array_unique($urls);
    }
    
    /**
     * Normalize relative URLs to absolute URLs
     */
    private function normalizeUrl($url) {
        if (filter_var($url, FILTER_VALIDATE_URL)) {
            return $url;
        }
        
        if (strpos($url, '/') === 0) {
            return $this->baseUrl . $url;
        }
        
        return $this->baseUrl . '/' . ltrim($url, '/');
    }
    
    /**
     * Check if URL belongs to target domain
     */
    private function isInternalUrl($url) {
        $parsedBase = parse_url($this->baseUrl);
        $parsedUrl = parse_url($url);
        
        return isset($parsedUrl['host']) && $parsedUrl['host'] === $parsedBase['host'];
    }
    
    /**
     * Perform comprehensive security checks
     */
    private function performSecurityChecks($url, $response) {
        echo "[+] Performing security checks on: $url\n";
        
        // Check for security headers
        $this->checkSecurityHeaders();
        
        // Check for common vulnerabilities
        $this->checkXSSVulnerability($url, $response);
        $this->checkSQLInjection($url);
        $this->checkDirectoryTraversal($url);
        $this->checkSensitiveFiles($url);
        $this->checkHTTPSRedirection($url);
    }
    
    /**
     * Check for security headers
     */
    private function checkSecurityHeaders() {
        $securityHeaders = [
            'X-Frame-Options' => 'Clickjacking protection',
            'X-XSS-Protection' => 'XSS protection',
            'X-Content-Type-Options' => 'MIME sniffing protection',
            'Strict-Transport-Security' => 'HTTPS enforcement',
            'Content-Security-Policy' => 'Content injection protection',
            'X-Content-Security-Policy' => 'Legacy CSP header'
        ];
        
        foreach ($securityHeaders as $header => $description) {
            if (!isset($this->headers[$header])) {
                $this->addVulnerability("Missing Security Header", 
                    "Missing $header header - $description", "Medium");
            }
        }
    }
    
    /**
     * Test for XSS vulnerabilities
     */
    private function checkXSSVulnerability($url, $response) {
        $xssPayloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            'javascript:alert("XSS")'
        ];
        
        foreach ($xssPayloads as $payload) {
            if (strpos($response, $payload) !== false) {
                $this->addVulnerability("Cross-Site Scripting (XSS)", 
                    "Potential XSS vulnerability detected with payload: $payload", "High");
            }
        }
    }
    
    /**
     * Test for SQL injection vulnerabilities
     */
    private function checkSQLInjection($url) {
        $sqlPayloads = [
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' /*",
            "'; DROP TABLE users; --"
        ];
        
        foreach ($sqlPayloads as $payload) {
            $testUrl = $url . (strpos($url, '?') ? '&' : '?') . "id=" . urlencode($payload);
            $ch = $this->initCurl($testUrl);
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($response && (strpos($response, 'SQL') !== false || 
                strpos($response, 'mysql') !== false || 
                strpos($response, 'ORA-') !== false)) {
                $this->addVulnerability("SQL Injection", 
                    "Potential SQL injection vulnerability with payload: $payload", "Critical");
            }
        }
    }
    
    /**
     * Test for directory traversal vulnerabilities
     */
    private function checkDirectoryTraversal($url) {
        $traversalPayloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ];
        
        foreach ($traversalPayloads as $payload) {
            $testUrl = $url . (strpos($url, '?') ? '&' : '?') . "file=" . urlencode($payload);
            $ch = $this->initCurl($testUrl);
            $response = curl_exec($ch);
            curl_close($ch);
            
            if ($response && (strpos($response, 'root:x:') !== false || 
                strpos($response, '[drivers]') !== false)) {
                $this->addVulnerability("Directory Traversal", 
                    "Potential directory traversal vulnerability with payload: $payload", "High");
            }
        }
    }
    
    /**
     * Check for sensitive files
     */
    private function checkSensitiveFiles($url) {
        $sensitiveFiles = [
            '/robots.txt',
            '/.htaccess',
            '/web.config',
            '/phpinfo.php',
            '/admin/',
            '/backup/',
            '/.git/',
            '/.svn/',
            '/config.php',
            '/wp-config.php'
        ];
        
        $baseUrl = parse_url($url, PHP_URL_SCHEME) . '://' . parse_url($url, PHP_URL_HOST);
        
        foreach ($sensitiveFiles as $file) {
            $testUrl = $baseUrl . $file;
            $ch = $this->initCurl($testUrl);
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($httpCode === 200) {
                $this->addVulnerability("Sensitive File Exposure", 
                    "Sensitive file accessible: $testUrl", "Medium");
            }
        }
    }
    
    /**
     * Check HTTPS redirection
     */
    private function checkHTTPSRedirection($url) {
        if (strpos($url, 'https://') === 0) {
            $httpUrl = str_replace('https://', 'http://', $url);
            $ch = $this->initCurl($httpUrl);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($httpCode !== 301 && $httpCode !== 302) {
                $this->addVulnerability("Missing HTTPS Redirection", 
                    "HTTP version accessible without redirect to HTTPS", "Medium");
            }
        }
    }
    
    /**
     * Add vulnerability to results
     */
    private function addVulnerability($type, $description, $severity) {
        $this->vulnerabilities[] = [
            'type' => $type,
            'description' => $description,
            'severity' => $severity,
            'timestamp' => date('Y-m-d H:i:s')
        ];
        echo "[!] $severity: $type - $description\n";
    }
    
    /**
     * Generate comprehensive security report
     */
    public function generateReport() {
        echo "\n" . str_repeat("=", 60) . "\n";
        echo "WEB SECURITY ASSESSMENT REPORT\n";
        echo str_repeat("=", 60) . "\n";
        echo "Target: " . $this->baseUrl . "\n";
        echo "Scan Date: " . date('Y-m-d H:i:s') . "\n";
        echo "URLs Crawled: " . count($this->visitedUrls) . "\n";
        echo "Vulnerabilities Found: " . count($this->vulnerabilities) . "\n\n";
        
        if (empty($this->vulnerabilities)) {
            echo "[+] No critical vulnerabilities detected.\n";
        } else {
            $severityCount = array_count_values(array_column($this->vulnerabilities, 'severity'));
            
            echo "VULNERABILITY SUMMARY:\n";
            echo "Critical: " . ($severityCount['Critical'] ?? 0) . "\n";
            echo "High: " . ($severityCount['High'] ?? 0) . "\n";
            echo "Medium: " . ($severityCount['Medium'] ?? 0) . "\n";
            echo "Low: " . ($severityCount['Low'] ?? 0) . "\n\n";
            
            echo "DETAILED FINDINGS:\n";
            echo str_repeat("-", 40) . "\n";
            
            foreach ($this->vulnerabilities as $vuln) {
                echo "[{$vuln['severity']}] {$vuln['type']}\n";
                echo "Description: {$vuln['description']}\n";
                echo "Detected: {$vuln['timestamp']}\n\n";
            }
        }
        
        echo "RECOMMENDATIONS:\n";
        echo "• Implement proper input validation and sanitization\n";
        echo "• Add security headers (CSP, HSTS, X-Frame-Options)\n";
        echo "• Regular security updates and patches\n";
        echo "• Use HTTPS encryption for all communications\n";
        echo "• Implement proper authentication and authorization\n";
        echo "• Regular security assessments and penetration testing\n";
        
        return $this->vulnerabilities;
    }
    
    /**
     * Save report to JSON file
     */
    public function saveReport($filename = null) {
        if (!$filename) {
            $filename = 'web_security_report_' . date('Ymd_His') . '.json';
        }
        
        $report = [
            'target' => $this->baseUrl,
            'scan_date' => date('Y-m-d H:i:s'),
            'urls_crawled' => $this->visitedUrls,
            'vulnerabilities' => $this->vulnerabilities,
            'total_urls' => count($this->visitedUrls),
            'total_vulnerabilities' => count($this->vulnerabilities)
        ];
        
        file_put_contents($filename, json_encode($report, JSON_PRETTY_PRINT));
        echo "\n[+] Report saved to: $filename\n";
    }
}

// CLI Usage
if (php_sapi_name() === 'cli') {
    if ($argc < 2) {
        echo "Usage: php web_crawler.php <target_url>\n";
        echo "Example: php web_crawler.php https://example.com\n";
        exit(1);
    }
    
    $targetUrl = $argv[1];
    
    echo "Web Security Crawler v1.0\n";
    echo "Author: Edwyn Moss\n";
    echo str_repeat("=", 40) . "\n";
    
    $crawler = new WebSecurityCrawler($targetUrl);
    $crawler->crawlSite();
    $vulnerabilities = $crawler->generateReport();
    $crawler->saveReport();
}
?> 