#!/usr/bin/env python3
"""
Rootsploix Professional License System
Advanced licensing module for Rootsploix cybersecurity tools

Author: Rootsploix
Version: 2.1.0
"""

import hashlib
import hmac
import json
import time
import os
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import requests

class RootsploixLicense:
    """Professional license validation system"""
    
    def __init__(self, tool_name: str, version: str = "2.1.0"):
        self.tool_name = tool_name
        self.version = version
        self.license_server = "https://api.rootsploix.com/license"
        self.demo_limits = {
            'max_scans': 10,
            'max_targets': 1,
            'advanced_features': False,
            'reporting': False,
            'threading': 1
        }
    
    def validate_license(self, license_key: str) -> Tuple[bool, Dict]:
        """
        Validate license key against Rootsploix servers
        
        Args:
            license_key (str): User's license key
            
        Returns:
            Tuple[bool, Dict]: (is_valid, license_info)
        """
        try:
            # Demo license check
            if license_key.upper() == "DEMO":
                return True, {
                    'status': 'demo',
                    'features': self.demo_limits,
                    'expires': None
                }
            
            # Professional license validation
            payload = {
                'tool': self.tool_name,
                'license': license_key,
                'version': self.version,
                'timestamp': int(time.time())
            }
            
            # Simulate license server check (would be real in production)
            if self._validate_key_format(license_key):
                return True, {
                    'status': 'professional',
                    'features': {
                        'max_scans': -1,  # unlimited
                        'max_targets': -1,
                        'advanced_features': True,
                        'reporting': True,
                        'threading': -1
                    },
                    'expires': None
                }
            else:
                return False, {'error': 'Invalid license key format'}
                
        except Exception as e:
            return False, {'error': f'License validation failed: {str(e)}'}
    
    def _validate_key_format(self, license_key: str) -> bool:
        """Validate license key format"""
        # Professional license format: RXPRO-XXXXX-XXXXX-XXXXX-XXXXX
        if license_key.startswith('RXPRO-'):
            parts = license_key.split('-')
            return len(parts) == 5 and all(len(part) == 5 for part in parts[1:])
        return False
    
    def get_demo_banner(self) -> str:
        """Get demo mode banner"""
        return f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                           🔥 ROOTSPLOIX PROFESSIONAL 🔥                      ║
║                                                                              ║
║  {self.tool_name:<68} ║
║  Version: {self.version:<59} ║
║                                                                              ║
║  🚨 DEMO MODE - LIMITED FEATURES 🚨                                          ║
║  • Maximum {self.demo_limits['max_scans']} scans per session                                              ║
║  • Basic features only                                                       ║
║  • No advanced reporting                                                     ║
║                                                                              ║
║  💎 Upgrade to Professional:                                                 ║
║  • Unlimited scans                                                           ║
║  • Advanced techniques                                                       ║
║  • Professional reporting                                                    ║
║  • Multi-threading support                                                   ║
║  • Priority support                                                          ║
║                                                                              ║
║  🛒 Purchase: https://rootsploix.gumroad.com/{self.tool_name.lower()}        ║
║  📧 Contact: rootsploix.pro@gmail.com                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    def get_professional_banner(self) -> str:
        """Get professional mode banner"""
        return f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                           🔥 ROOTSPLOIX PROFESSIONAL 🔥                      ║
║                                                                              ║
║  {self.tool_name:<68} ║
║  Version: {self.version:<59} ║
║                                                                              ║
║  ✅ PROFESSIONAL LICENSE ACTIVE                                              ║
║  • Unlimited scanning capabilities                                           ║
║  • All advanced features unlocked                                            ║
║  • Professional reporting enabled                                            ║
║  • Multi-threading optimized                                                 ║
║                                                                              ║
║  Thank you for supporting Rootsploix! 💎                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    def check_demo_limits(self, current_usage: Dict) -> Tuple[bool, str]:
        """
        Check if demo limits are exceeded
        
        Args:
            current_usage (Dict): Current usage statistics
            
        Returns:
            Tuple[bool, str]: (within_limits, message)
        """
        if current_usage.get('scan_count', 0) >= self.demo_limits['max_scans']:
            return False, f"Demo limit reached: {self.demo_limits['max_scans']} scans maximum"
        
        if current_usage.get('target_count', 0) > self.demo_limits['max_targets']:
            return False, f"Demo limit: {self.demo_limits['max_targets']} target maximum"
        
        return True, "Within demo limits"
    
    @staticmethod
    def generate_license_prompt() -> str:
        """Generate license key input prompt"""
        return """
╔═══════════════════════════════════════════════════════════════╗
║                    🔐 LICENSE ACTIVATION                      ║
║                                                               ║
║  Enter your Rootsploix Professional license key:             ║
║  Format: RXPRO-XXXXX-XXXXX-XXXXX-XXXXX                       ║
║                                                               ║
║  Or type 'DEMO' for limited demo mode                        ║
║                                                               ║
║  Purchase license: https://rootsploix.gumroad.com            ║
╚═══════════════════════════════════════════════════════════════╝

License Key: """

# Usage example
if __name__ == "__main__":
    license_system = RootsploixLicense("TestTool")
    
    # Test demo mode
    is_valid, info = license_system.validate_license("DEMO")
    print(f"Demo validation: {is_valid}, Info: {info}")
    print(license_system.get_demo_banner())
    
    # Test professional license
    is_valid, info = license_system.validate_license("RXPRO-ABC12-DEF34-GHI56-JKL78")
    print(f"Professional validation: {is_valid}, Info: {info}")
    if is_valid:
        print(license_system.get_professional_banner())