#!/usr/bin/env python3
"""
WebRoots - Advanced Web Vulnerability Scanner
Professional web application security testing tool by Rootsploix

Features:
- SQL Injection detection
- XSS vulnerability scanning  
- Directory traversal testing
- Authentication bypass testing
- Security header analysis
- SSL/TLS configuration testing
- Professional reporting

Author: Rootsploix
Version: 2.1.0
License: Commercial
Price: $599 (Professional) / $1299 (Enterprise)
"""

import requests
import urllib.parse
import argparse
import json
import time
import sys
import re
import ssl
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple
from rootsploix_license import RootsploixLicense

class WebRoots:
    """Advanced web vulnerability scanner"""
    
    def __init__(self):
        self.license = RootsploixLicense("WebRoots", "2.1.0")
        self.is_licensed = False
        self.license_info = {}
        self.scan_stats = {'scan_count': 0, 'url_count': 0}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebRoots/2.1.0 Professional Scanner'
        })
        
        # Vulnerability test payloads (demo version limited)
        self.sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT null--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "admin'--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>"
        ]
        
        self.lfi_payloads = [
            "../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        # Security headers to check
        self.security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-XSS-Protection': 'XSS filtering',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content security policy',
            'Referrer-Policy': 'Referrer policy',
            'Feature-Policy': 'Feature policy'
        }
    
    def authenticate(self, license_key: str = None) -> bool:
        """Authenticate with license system"""
        if not license_key:
            print(self.license.generate_license_prompt(), end="")
            license_key = input().strip()
        
        self.is_licensed, self.license_info = self.license.validate_license(license_key)
        
        if self.is_licensed:
            if self.license_info['status'] == 'demo':
                print(self.license.get_demo_banner())
            else:
                print(self.license.get_professional_banner())
            return True
        else:
            print(f"❌ License validation failed: {self.license_info.get('error', 'Unknown error')}")
            return False
    
    def crawl_website(self, base_url: str, max_depth: int = 2) -> List[str]:
        """Crawl website to discover URLs"""
        found_urls = set([base_url])
        to_crawl = [base_url]
        crawled = set()
        
        # Demo limitations
        max_urls = 20 if self.license_info.get('status') == 'demo' else 100
        max_depth = min(max_depth, 1 if self.license_info.get('status') == 'demo' else max_depth)
        
        print(f"🕷️  Crawling {base_url} (max depth: {max_depth})...")
        
        for depth in range(max_depth):
            current_level = to_crawl.copy()
            to_crawl = []
            
            for url in current_level:
                if url in crawled or len(found_urls) >= max_urls:
                    continue
                
                try:
                    crawled.add(url)
                    response = self.session.get(url, timeout=10, verify=False)
                    
                    if response.status_code == 200 and 'text/html' in response.headers.get('content-type', ''):
                        # Simple link extraction
                        links = re.findall(r'href=["\']([^"\']+)["\']', response.text)
                        
                        for link in links:
                            # Convert relative URLs to absolute
                            full_url = urllib.parse.urljoin(url, link)
                            
                            # Only include same domain
                            if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(base_url).netloc:
                                if full_url not in found_urls and len(found_urls) < max_urls:
                                    found_urls.add(full_url)
                                    to_crawl.append(full_url)
                    
                    print(f"  ✅ Crawled: {url}")
                    
                except Exception as e:
                    print(f"  ❌ Error crawling {url}: {str(e)[:50]}")
                    continue
        
        return list(found_urls)[:max_urls]
    
    def test_sql_injection(self, url: str, params: Dict = None) -> List[Dict]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            # Try to extract parameters from URL
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not params:
            return vulnerabilities
        
        # Demo version limited payloads
        payloads = self.sql_payloads[:3] if self.license_info.get('status') == 'demo' else self.sql_payloads
        
        print(f"🔍 Testing SQL injection on {url}")
        
        for param_name in params:
            for payload in payloads:
                try:
                    # Test GET parameter
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=10, verify=False)
                    
                    # Check for SQL error indicators
                    sql_errors = [
                        'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
                        'odbc', 'postgresql', 'warning: mysql', 'valid mysql result',
                        'mysqldump', 'php error', 'mysql error', 'ora-01756'
                    ]
                    
                    response_lower = response.text.lower()
                    for error in sql_errors:
                        if error in response_lower:
                            vulnerability = {
                                'type': 'SQL Injection',
                                'severity': 'High',
                                'parameter': param_name,
                                'payload': payload,
                                'url': url,
                                'evidence': f"SQL error detected: {error}"
                            }
                            
                            # Professional version includes more detailed analysis
                            if self.license_info.get('status') == 'professional':
                                vulnerability.update({
                                    'response_code': response.status_code,
                                    'response_length': len(response.text),
                                    'exploitation_risk': self._assess_sqli_risk(response.text)
                                })
                            
                            vulnerabilities.append(vulnerability)
                            print(f"  🚨 SQL Injection found in parameter '{param_name}'")
                            break
                
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def test_xss_vulnerabilities(self, url: str, params: Dict = None) -> List[Dict]:
        """Test for Cross-Site Scripting vulnerabilities"""
        vulnerabilities = []
        
        if not params:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if not params:
            return vulnerabilities
        
        # Demo version limited payloads
        payloads = self.xss_payloads[:3] if self.license_info.get('status') == 'demo' else self.xss_payloads
        
        print(f"🔍 Testing XSS vulnerabilities on {url}")
        
        for param_name in params:
            for payload in payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=10, verify=False)
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'Medium',
                            'parameter': param_name,
                            'payload': payload,
                            'url': url,
                            'evidence': 'Payload reflected in response'
                        }
                        
                        # Professional version includes context analysis
                        if self.license_info.get('status') == 'professional':
                            vulnerability.update({
                                'context': self._analyze_xss_context(response.text, payload),
                                'exploitation_difficulty': self._assess_xss_difficulty(response.text, payload)
                            })
                        
                        vulnerabilities.append(vulnerability)
                        print(f"  🚨 XSS vulnerability found in parameter '{param_name}'")
                        break
                
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def test_directory_traversal(self, base_url: str) -> List[Dict]:
        """Test for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        # Demo version limited payloads
        payloads = self.lfi_payloads[:2] if self.license_info.get('status') == 'demo' else self.lfi_payloads
        
        print(f"🔍 Testing directory traversal on {base_url}")
        
        # Common vulnerable parameters
        test_params = ['file', 'page', 'include', 'path', 'document', 'folder', 'root']
        
        for param in test_params:
            for payload in payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check for file inclusion indicators
                    lfi_indicators = ['root:x:', 'bin/bash', '[boot loader]', 'windows\\system32']
                    
                    response_lower = response.text.lower()
                    for indicator in lfi_indicators:
                        if indicator in response_lower:
                            vulnerability = {
                                'type': 'Directory Traversal',
                                'severity': 'High',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'evidence': f"File inclusion detected: {indicator}"
                            }
                            
                            vulnerabilities.append(vulnerability)
                            print(f"  🚨 Directory traversal found with parameter '{param}'")
                            break
                
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def check_security_headers(self, url: str) -> Dict:
        """Check for security headers"""
        print(f"🔍 Checking security headers for {url}")
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            headers = response.headers
            
            results = {
                'url': url,
                'missing_headers': [],
                'present_headers': {},
                'security_score': 0
            }
            
            for header, description in self.security_headers.items():
                if header in headers:
                    results['present_headers'][header] = headers[header]
                    results['security_score'] += 1
                    print(f"  ✅ {header}: {headers[header]}")
                else:
                    results['missing_headers'].append(header)
                    print(f"  ❌ Missing: {header} ({description})")
            
            results['security_score'] = (results['security_score'] / len(self.security_headers)) * 100
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    def check_ssl_configuration(self, url: str) -> Dict:
        """Professional feature: SSL/TLS configuration analysis"""
        if self.license_info.get('status') != 'professional':
            return {'error': 'SSL analysis requires Professional license'}
        
        print(f"🔍 Analyzing SSL/TLS configuration for {url}")
        
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.netloc
            port = 443 if parsed.scheme == 'https' else 80
            
            if port != 443:
                return {'error': 'SSL analysis only available for HTTPS URLs'}
            
            # Get SSL certificate info
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            return {
                'certificate': {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert['version'],
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter']
                },
                'cipher_suite': cipher[0] if cipher else 'Unknown',
                'protocol_version': version,
                'security_assessment': self._assess_ssl_security(cipher, version)
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    def _assess_sqli_risk(self, response_text: str) -> str:
        """Professional feature: Assess SQL injection exploitation risk"""
        if 'union' in response_text.lower():
            return 'Critical - UNION queries possible'
        elif 'mysql' in response_text.lower():
            return 'High - Database errors exposed'
        else:
            return 'Medium - Error-based injection'
    
    def _analyze_xss_context(self, response_text: str, payload: str) -> str:
        """Professional feature: Analyze XSS context"""
        payload_index = response_text.find(payload)
        if payload_index == -1:
            return 'Not reflected'
        
        context = response_text[max(0, payload_index-50):payload_index+len(payload)+50]
        
        if '<script' in context.lower():
            return 'Script context'
        elif 'href=' in context.lower():
            return 'Attribute context'
        elif '<' in context and '>' in context:
            return 'HTML context'
        else:
            return 'Text context'
    
    def _assess_xss_difficulty(self, response_text: str, payload: str) -> str:
        """Professional feature: Assess XSS exploitation difficulty"""
        if 'script' in payload.lower() and payload in response_text:
            return 'Easy - Direct script execution'
        elif 'onerror' in payload.lower() and payload in response_text:
            return 'Easy - Event handler execution'
        else:
            return 'Medium - Requires encoding bypass'
    
    def _assess_ssl_security(self, cipher: tuple, version: str) -> str:
        """Professional feature: Assess SSL/TLS security"""
        if not cipher:
            return 'Poor - No cipher information'
        
        cipher_name = cipher[0].lower()
        
        if 'rc4' in cipher_name or 'des' in cipher_name:
            return 'Poor - Weak cipher detected'
        elif version in ['TLSv1', 'SSLv3', 'SSLv2']:
            return 'Poor - Outdated protocol version'
        elif 'aes' in cipher_name and version == 'TLSv1.2':
            return 'Good - Strong cipher and protocol'
        elif version == 'TLSv1.3':
            return 'Excellent - Latest protocol version'
        else:
            return 'Medium - Acceptable configuration'
    
    def scan_website(self, url: str, scan_types: List[str] = None) -> Dict:
        """Main website vulnerability scanning function"""
        
        # Check demo limits
        if self.license_info.get('status') == 'demo':
            self.scan_stats['scan_count'] += 1
            self.scan_stats['url_count'] = 1
            
            within_limits, message = self.license.check_demo_limits(self.scan_stats)
            if not within_limits:
                print(f"❌ {message}")
                print("💎 Upgrade to Professional for unlimited web scanning!")
                return {'error': message}
        
        if not scan_types:
            scan_types = ['crawl', 'sql_injection', 'xss', 'directory_traversal', 'headers']
            if self.license_info.get('status') == 'professional':
                scan_types.append('ssl_analysis')
        
        print(f"🎯 Starting web vulnerability scan for {url}")
        print(f"📋 Scan types: {', '.join(scan_types)}")
        
        start_time = time.time()
        results = {
            'target_url': url,
            'scan_types': scan_types,
            'vulnerabilities': [],
            'security_headers': {},
            'ssl_analysis': {},
            'crawled_urls': [],
            'scan_time': 0,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Website crawling
            if 'crawl' in scan_types:
                results['crawled_urls'] = self.crawl_website(url)
                print(f"✅ Crawled {len(results['crawled_urls'])} URLs")
            else:
                results['crawled_urls'] = [url]
            
            # Vulnerability testing
            for test_url in results['crawled_urls'][:10]:  # Limit URLs in demo
                if self.license_info.get('status') == 'demo' and len([v for v in results['vulnerabilities']]) >= 5:
                    print("⚠️  Demo version limited to 5 vulnerability tests")
                    break
                
                # Parse URL parameters
                parsed = urllib.parse.urlparse(test_url)
                params = dict(urllib.parse.parse_qsl(parsed.query))
                
                if 'sql_injection' in scan_types and params:
                    sqli_vulns = self.test_sql_injection(test_url, params)
                    results['vulnerabilities'].extend(sqli_vulns)
                
                if 'xss' in scan_types and params:
                    xss_vulns = self.test_xss_vulnerabilities(test_url, params)
                    results['vulnerabilities'].extend(xss_vulns)
                
                if 'directory_traversal' in scan_types:
                    lfi_vulns = self.test_directory_traversal(test_url)
                    results['vulnerabilities'].extend(lfi_vulns)
            
            # Security headers check
            if 'headers' in scan_types:
                results['security_headers'] = self.check_security_headers(url)
            
            # SSL analysis (Professional only)
            if 'ssl_analysis' in scan_types and self.license_info.get('status') == 'professional':
                results['ssl_analysis'] = self.check_ssl_configuration(url)
            
            results['scan_time'] = time.time() - start_time
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            results['scan_time'] = time.time() - start_time
            return results
    
    def generate_report(self, scan_results: Dict) -> str:
        """Generate detailed vulnerability report"""
        if self.license_info.get('status') != 'professional':
            return "Professional reporting requires license upgrade"
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          🕷️  WEBROOTS REPORT 🕷️                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

Target URL: {scan_results['target_url']}
Scan Duration: {scan_results['scan_time']:.2f} seconds
URLs Crawled: {len(scan_results.get('crawled_urls', []))}
Vulnerabilities Found: {len(scan_results.get('vulnerabilities', []))}
Timestamp: {scan_results['timestamp']}

VULNERABILITY SUMMARY:
{'='*80}
"""
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in scan_results.get('vulnerabilities', []):
            vuln_type = vuln['type']
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        for vuln_type, vulns in vuln_types.items():
            report += f"\\n🚨 {vuln_type}: {len(vulns)} found\\n"
            for vuln in vulns[:3]:  # Show first 3 of each type
                report += f"   • {vuln['url']} (Parameter: {vuln.get('parameter', 'N/A')})\\n"
                report += f"     Severity: {vuln['severity']} | Evidence: {vuln['evidence']}\\n"
        
        # Security headers analysis
        if 'security_headers' in scan_results:
            headers = scan_results['security_headers']
            if not headers.get('error'):
                report += f"\\nSECURITY HEADERS ANALYSIS:\\n{'='*80}\\n"
                report += f"Security Score: {headers.get('security_score', 0):.1f}%\\n\\n"
                
                if headers.get('missing_headers'):
                    report += "Missing Headers:\\n"
                    for header in headers['missing_headers'][:5]:
                        report += f"  ❌ {header}\\n"
        
        # SSL analysis
        if 'ssl_analysis' in scan_results and not scan_results['ssl_analysis'].get('error'):
            ssl_info = scan_results['ssl_analysis']
            report += f"\\nSSL/TLS ANALYSIS:\\n{'='*80}\\n"
            report += f"Protocol Version: {ssl_info.get('protocol_version', 'Unknown')}\\n"
            report += f"Cipher Suite: {ssl_info.get('cipher_suite', 'Unknown')}\\n"
            report += f"Security Assessment: {ssl_info.get('security_assessment', 'Unknown')}\\n"
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description="WebRoots - Advanced Web Vulnerability Scanner by Rootsploix",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webroots.py --url https://example.com --license DEMO
  python webroots.py --url https://target.com --scan sql_injection,xss --license RXPRO-XXXXX-XXXXX-XXXXX-XXXXX
  python webroots.py --url https://victim.org --all --output vuln_report.txt
        """
    )
    
    parser.add_argument('--url', '-u', required=True, help='Target URL to scan')
    parser.add_argument('--scan', '-s', help='Scan types (comma-separated): sql_injection,xss,directory_traversal,headers,ssl_analysis')
    parser.add_argument('--all', '-a', action='store_true', help='Run all available scans')
    parser.add_argument('--license', '-l', help='License key (or DEMO for demo mode)')
    parser.add_argument('--output', '-o', help='Output file for vulnerability report (Professional only)')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = WebRoots()
    
    # Authenticate
    if not scanner.authenticate(args.license):
        sys.exit(1)
    
    # Determine scan types
    scan_types = None
    if args.all:
        scan_types = ['crawl', 'sql_injection', 'xss', 'directory_traversal', 'headers']
        if scanner.license_info.get('status') == 'professional':
            scan_types.append('ssl_analysis')
    elif args.scan:
        scan_types = [s.strip() for s in args.scan.split(',')]
    
    # Perform scan
    try:
        print(f"🚀 Starting web vulnerability scan for {args.url}...")
        results = scanner.scan_website(args.url, scan_types)
        
        if 'error' not in results:
            print(f"\\n🎉 Scan completed! Found {len(results.get('vulnerabilities', []))} vulnerabilities in {results['scan_time']:.2f} seconds")
            
            # Generate professional report
            if scanner.license_info.get('status') == 'professional':
                report = scanner.generate_report(results)
                print(report)
                
                # Save to file if requested
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(report)
                    print(f"💾 Vulnerability report saved to {args.output}")
            
            # JSON output
            if args.json:
                print("\\n📋 Results (JSON):")
                print(json.dumps(results, indent=2))
    
    except KeyboardInterrupt:
        print("\\n⚠️  Web scan interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()