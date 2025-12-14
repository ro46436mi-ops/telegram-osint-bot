"""
API Handler - Manages all external API calls
"""
import os
import requests
import json
from typing import Dict, Any, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class APIHandler:
    """Handles all API communications"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Telegram-OSINT-Bot/1.0'
        })
        
        # API endpoints
        self.apis = {
            'ipinfo': {
                'url': 'https://ipinfo.io/{ip}/json',
                'token': os.getenv('IPINFO_TOKEN'),
                'required': False
            },
            'numverify': {
                'url': 'http://apilayer.net/api/validate',
                'key': os.getenv('NUMVERIFY_KEY'),
                'required': False
            },
            'whoisfreaks': {
                'url': 'https://api.whoisfreaks.com/v1.0/whois',
                'key': os.getenv('WHOISFREAKS_KEY'),
                'required': False
            },
            'serpapi': {
                'url': 'https://serpapi.com/search',
                'key': os.getenv('SERPAPI_KEY'),
                'required': False
            },
            'hibp': {
                'url': 'https://haveibeenpwned.com/api/v2/breachedaccount/{email}',
                'headers': {
                    'User-Agent': os.getenv('HIBP_USER_AGENT', 'Telegram-OSINT-Bot/1.0')
                },
                'required': False
            }
        }
    
    def check_api_status(self) -> Dict[str, bool]:
        """Check which APIs are available"""
        status = {}
        for name, config in self.apis.items():
            if name in ['ipinfo', 'numverify', 'whoisfreaks', 'serpapi']:
                status[name] = bool(config.get('key') or config.get('token'))
            else:
                status[name] = True  # HIBP doesn't need key
        return status
    
    def ip_lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """Lookup IP information"""
        try:
            token = self.apis['ipinfo']['token']
            if not token:
                return {"error": "IPINFO_TOKEN not set in environment"}
            
            url = self.apis['ipinfo']['url'].format(ip=ip)
            params = {'token': token}
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"IP lookup failed: {e}")
            return {"error": f"IP lookup failed: {str(e)}"}
    
    def phone_lookup(self, phone: str) -> Optional[Dict[str, Any]]:
        """Lookup phone number information"""
        try:
            key = self.apis['numverify']['key']
            if not key:
                return {"error": "NUMVERIFY_KEY not set in environment"}
            
            url = self.apis['numverify']['url']
            params = {
                'access_key': key,
                'number': phone,
                'format': 1
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Phone lookup failed: {e}")
            return {"error": f"Phone lookup failed: {str(e)}"}
    
    def email_breach_check(self, email: str) -> Optional[Dict[str, Any]]:
        """Check if email was in data breaches"""
        try:
            url = self.apis['hibp']['url'].format(email=email)
            headers = self.apis['hibp']['headers']
            
            # HIBP v2 requires User-Agent header
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 404:
                return {"safe": True, "message": "No breaches found"}
            elif response.status_code == 200:
                breaches = response.json()
                return {
                    "breached": True,
                    "count": len(breaches),
                    "breaches": breaches[:5]  # Return first 5 breaches
                }
            else:
                return {"error": f"API returned status {response.status_code}"}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Email breach check failed: {e}")
            return {"error": f"Email check failed: {str(e)}"}
    
    def whois_lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """WHOIS domain lookup"""
        try:
            key = self.apis['whoisfreaks']['key']
            if not key:
                return {"error": "WHOISFREAKS_KEY not set in environment"}
            
            url = self.apis['whoisfreaks']['url']
            params = {
                'apiKey': key,
                'domain': domain,
                'whois': 'live'
            }
            
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"WHOIS lookup failed: {e}")
            return {"error": f"WHOIS lookup failed: {str(e)}"}
    
    def reverse_image_search(self, image_url: str) -> Optional[Dict[str, Any]]:
        """Reverse image search"""
        try:
            key = self.apis['serpapi']['key']
            if not key:
                return {"error": "SERPAPI_KEY not set in environment"}
            
            url = self.apis['serpapi']['url']
            params = {
                'engine': 'google_reverse_image',
                'api_key': key,
                'image_url': image_url
            }
            
            response = self.session.get(url, params=params, timeout=15)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Reverse image search failed: {e}")
            return {"error": f"Reverse image search failed: {str(e)}"}

# Global instance
api_handler = APIHandler()
