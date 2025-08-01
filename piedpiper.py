#!/usr/bin/env python3
import os
import requests
import re
import time
import json
import argparse
import urllib.parse
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
from bs4 import BeautifulSoup
import random
import sqlite3
from datetime import datetime
import hashlib
from urllib.parse import urlparse

LOGO = r"""

 
▄▖▘   ▌  ▄▖▘      
▙▌▌█▌▛▌  ▙▌▌▛▌█▌▛▘
▌ ▌▙▖▙▌  ▌ ▌▙▌▙▖▌ 
            ▌     😈 OSINT AI - CHAT << Leak Finder >>

By KL3FT3Z (https://github.com/toxy4ny)

                                     .  dc,F  _,
                                   -cc$P""?$b$$cc'
                                .,cc$Lccc,d"   "$-'
                          ,d$$b."$$P",z $$$P"?$ $bd'
                          ?$$$$' $" ,$'d$P,$$,?$$$"'
                           `"".zeec`",d$$  `$$ $$$$P'
                             $$$$$$$c`"?b  ,$$ $$$$P'".,,,,_
                             $$$$$$$$,$$c,"$P'c$$P"d$$$$$$$$$
                           Pb,"?$$$$$$$$$$c <$$$$b ",,ccccd$$
                             $$r .""?$$$$$$L ?$$$$c`$$$$$$$$"
                             `?$,`:`  "$$$$$ <$$$r"r`?$??""
 =,                             `?   ..`$$$P dF "?
  `"=c,,_                  "?$$$>`\`-::,$P",d"zP
        3$b,,_ ,,,,,,,,,,,,, ,cc..`"ccdP',,,cc==""
     +=""' `"" CCCCCCCCCCCC 4$$C  '% . =cu .,c,
               `CCCCCCCCCCC>,,  c?,,,"?bdP <CCCCCc,                   ,,
                `''''''''    ,CC xX <Ccc,.CCCCCCCCCCCccc,,,.   ,,,,,==
                           ,CC',XXX <CCCCCc`CCCCCCCCCCCCCC',,,,""?L `
                         ,CCC',XXXX <CCCCCCCc`'<CCCCCCCC',CCC>'   ?, `"
                      ,CCCC'<XXXXX <CCCCCCCCCCc  `'<<C>,C>'
                     ,CCCCC'<XX>'XX <CCCCCCCCCCCC,
                    c<CCCCC '',d,`', CCCCCCCCCCCCC>
                    ,cc,.`'dcd$$$c$$,`CCCCCC>>>>>>>
                   c$$$$$$$$$$$$$$$$L `''.,,ccc ccu
             J$.  J$$$$$,?$$$$$$$$$$$e$$$$$$$$P ""
             ?$$  $$$$$$$c,??$$$$$$?$$?$$$$$$$
             `?$,`$$$P""       `   ?`?r?$$$$$$r
              `hc ""                    $$$$$$$
                                        `?$$$$$c
                                           `"?$$b
                                               "$b
                                                ,dk
                                                `?$ 
"""

def banner():

    os.system("cls" if os.name == "nt" else "clear")
    print(LOGO)
    print("\n")

@dataclass
class LeakResult:
    
    url: str
    title: str
    snippet: str
    service: str
    leak_type: str
    severity: str
    timestamp: str
    confidence_score: float  
    ai_chat_indicators: List[str] 
    hash_id: str = None
    
    def __post_init__(self):
        if not self.hash_id:
            self.hash_id = hashlib.md5(f"{self.url}{self.title}".encode()).hexdigest()

class PreciseAIServiceDorks:
        
    AI_SERVICES = {
        'chatgpt': {
            'domains': ['chatgpt.com', 'chat.openai.com'],
            'valid_paths': ['/share/', '/c/', '/g/'],
            'dorks': [
                'site:chatgpt.com/share intitle:"ChatGPT"',
                'site:chatgpt.com/share "I need help" OR "Can you help" OR "Please help"',
                'site:chatgpt.com/share "resume" OR "CV" OR "curriculum vitae"',
                'site:chatgpt.com/share "password" OR "login" OR "credentials"',
                'site:chatgpt.com/share "API key" OR "secret key" OR "access token"',
                'site:chatgpt.com/share "personal information" OR "private data"',
                'site:chatgpt.com/share "confidential" OR "internal" OR "sensitive"',
                'site:chatgpt.com/share "email" OR "phone number" OR "address"',
                'site:chatgpt.com/share "write a" OR "create a" OR "generate"',
                'site:chatgpt.com/share "As an AI" OR "I\'m ChatGPT" OR "I\'m an AI"',
                'site:chatgpt.com/share inurl:"/c/" OR inurl:"/share/"'
            ]
        },
        'claude': {
            'domains': ['claude.ai'],
            'valid_paths': ['/chat/', '/conversation/'],
            'dorks': [
                'site:claude.ai/chat intitle:"Claude"',
                'site:claude.ai/chat "I\'m Claude" OR "I\'m Anthropic\'s AI"',
                'site:claude.ai/chat "help me" OR "assist me" OR "can you"',
                'site:claude.ai/chat "personal" OR "confidential" OR "private"',
                'site:claude.ai/chat "resume" OR "CV" OR "application"',
                'site:claude.ai/chat "password" OR "credentials" OR "login"',
                'site:claude.ai/chat "API" OR "key" OR "token"'
            ]
        },
        'perplexity': {
            'domains': ['perplexity.ai'],
            'valid_paths': ['/search/', '/chat/'],
            'dorks': [
                'site:perplexity.ai "Sources:" OR "Answer:" OR "Follow-up"',
                'site:perplexity.ai intitle:"Search" OR intitle:"Chat"',
                'site:perplexity.ai "personal information" OR "confidential"'
            ]
        },
        'character_ai': {
            'domains': ['character.ai', 'beta.character.ai'],
            'valid_paths': ['/chat/', '/character/'],
            'dorks': [
                'site:character.ai/chat intitle:"Character.AI"',
                'site:character.ai "private conversation" OR "personal chat"',
                'site:character.ai/chat "roleplay" OR "character"'
            ]
        },
        'poe': {
            'domains': ['poe.com'],
            'valid_paths': ['/chat/', '/s/'],
            'dorks': [
                'site:poe.com/chat OR site:poe.com/s',
                'site:poe.com "Claude" OR "ChatGPT" OR "GPT-4"',
                'site:poe.com "conversation" OR "chat"'
            ]
        },
        'bard': {
            'domains': ['bard.google.com'],
            'valid_paths': ['/chat/', '/conversation/'],
            'dorks': [
                'site:bard.google.com "I\'m Bard" OR "Google\'s AI"',
                'site:bard.google.com "conversation" OR "chat"'
            ]
        }
    }

    @classmethod
    def get_all_dorks(cls) -> List[tuple]:
        
        all_dorks = []
        for service, data in cls.AI_SERVICES.items():
            for dork in data['dorks']:
                all_dorks.append((service, dork))
        return all_dorks

class AIContentValidator:
        
    AI_CHAT_INDICATORS = {
        'chatgpt': [
            "I'm ChatGPT", "As an AI", "I'm an AI assistant", "OpenAI",
            "I can help", "I'd be happy to", "ChatGPT response",
            "As a language model", "I don't have personal", "I cannot browse"
        ],
        'claude': [
            "I'm Claude", "I'm Anthropic's AI", "Claude here",
            "I'm an AI assistant created by Anthropic",
            "I'd be happy to help", "I should mention that",
            "I aim to be helpful"
        ],
        'bard': [
            "I'm Bard", "Google's AI", "I'm a large language model",
            "I'm powered by PaLM", "I'm still learning"
        ],
        'perplexity': [
            "Sources:", "Based on the search results", "According to",
            "Follow-up questions:", "Answer:", "Here's what I found"
        ],
        'character_ai': [
            "Character.AI", "*character name*", "roleplay", "I am ",
            "*actions*", "*thoughts*"
        ]
    }
    
    SENSITIVE_DATA_PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'[\+]?[1-9]?[0-9]{7,15}',
        'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'api_key': r'\b[A-Za-z0-9_-]{20,}\b',
        'password_pattern': r'(?:password|pass|pwd)[\s:=]+[^\s]+',
        'private_key': r'-----BEGIN.*PRIVATE KEY-----',
        'address': r'\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln)',
        'personal_info': r'(?:my name is|I am|I\'m)\s+[A-Z][a-z]+\s+[A-Z][a-z]+',
        'resume_keywords': r'(?:experience|education|skills|employment|graduated|degree|university|college)',
        'financial': r'(?:salary|income|bank|account|routing|social security)',
        'medical': r'(?:medical|health|diagnosis|prescription|doctor|hospital)',
        'legal': r'(?:lawyer|legal|court|lawsuit|settlement|contract)',
        'internal_docs': r'(?:confidential|internal|proprietary|NDA|non-disclosure)'
    }
    
    def validate_ai_chat_url(self, url: str, service: str) -> tuple[bool, float]:
       
        try:
            parsed = urlparse(url)
            service_data = PreciseAIServiceDorks.AI_SERVICES.get(service, {})
            
            valid_domains = service_data.get('domains', [])
            if not any(domain in parsed.netloc for domain in valid_domains):
                return False, 0.0
            
            valid_paths = service_data.get('valid_paths', [])
            if not any(path in parsed.path for path in valid_paths):
                return False, 0.2
            
            confidence = 0.5

            if service == 'chatgpt':
                if '/share/' in parsed.path and len(parsed.path) > 10:
                    confidence += 0.3
                if '/c/' in parsed.path:
                    confidence += 0.2
            
            elif service == 'claude':
                if '/chat/' in parsed.path:
                    confidence += 0.3
                    
            elif service == 'character_ai':
                if '/chat/' in parsed.path or '/character/' in parsed.path:
                    confidence += 0.3
            
            return True, min(confidence, 1.0)
            
        except Exception:
            return False, 0.0
    
    def analyze_content_for_ai_indicators(self, text: str, service: str) -> tuple[List[str], float]:
        
        indicators_found = []
        text_lower = text.lower()
        
        service_indicators = self.AI_CHAT_INDICATORS.get(service, [])
        for indicator in service_indicators:
            if indicator.lower() in text_lower:
                indicators_found.append(f"AI_INDICATOR: {indicator}")
        
        general_indicators = [
            "as an ai", "i'm an ai", "artificial intelligence",
            "language model", "i cannot", "i don't have access",
            "i'm not able to", "i can't browse", "i don't have personal",
            "i'm designed to", "my purpose is", "i was created"
        ]
        
        for indicator in general_indicators:
            if indicator in text_lower:
                indicators_found.append(f"GENERAL_AI: {indicator}")
        
        confidence = min(len(indicators_found) * 0.3, 1.0)
        
        return indicators_found, confidence
    
    def detect_sensitive_data(self, text: str) -> Dict[str, List[str]]:
        
        findings = {}
        
        for data_type, pattern in self.SENSITIVE_DATA_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                
                valid_matches = []
                for match in matches:
                    if self._is_valid_sensitive_data(match, data_type):
                        valid_matches.append(match)
                
                if valid_matches:
                    findings[data_type] = valid_matches
        
        return findings
    
    def _is_valid_sensitive_data(self, match: str, data_type: str) -> bool:
                
        false_positives = {
            'email': ['example@example.com', 'test@test.com', 'user@domain.com'],
            'phone': ['1234567890', '0000000000'],
            'api_key': ['your_api_key_here', 'api_key_here', 'insert_api_key']
        }
        
        if data_type in false_positives:
            return match.lower() not in [fp.lower() for fp in false_positives[data_type]]
        
        return True

class PreciseLeakAnalyzer:
        
    def __init__(self):
        self.validator = AIContentValidator()
    
    def analyze_result(self, result: Dict, service: str) -> Optional[LeakResult]:
        
        is_valid_url, url_confidence = self.validator.validate_ai_chat_url(result['url'], service)
        if not is_valid_url:
            return None
        
        full_text = f"{result['title']} {result['snippet']}"
        ai_indicators, ai_confidence = self.validator.analyze_content_for_ai_indicators(full_text, service)
        
        sensitive_findings = self.validator.detect_sensitive_data(full_text)
        
        total_confidence = (url_confidence + ai_confidence) / 2
       
        if total_confidence < 0.3:
            return None
        
        leak_types = []
        if sensitive_findings:
            leak_types.extend(sensitive_findings.keys())
        
        severity = self._calculate_severity(sensitive_findings, ai_indicators)
        
        if not ai_indicators and not sensitive_findings:
            return None
        
        return LeakResult(
            url=result['url'],
            title=result['title'],
            snippet=result['snippet'],
            service=service,
            leak_type=', '.join(leak_types) if leak_types else 'ai_conversation',
            severity=severity,
            timestamp=datetime.now().isoformat(),
            confidence_score=total_confidence,
            ai_chat_indicators=ai_indicators
        )
    
    def _calculate_severity(self, sensitive_findings: Dict, ai_indicators: List[str]) -> str:
        
        if not sensitive_findings and not ai_indicators:
            return 'info'
        
        critical_types = ['password_pattern', 'private_key', 'ssn', 'credit_card', 'financial']
        high_types = ['email', 'phone', 'api_key', 'personal_info', 'medical', 'legal']
        medium_types = ['address', 'resume_keywords', 'internal_docs']
        
        found_types = set(sensitive_findings.keys())
        
        if found_types.intersection(critical_types):
            return 'critical'
        elif found_types.intersection(high_types):
            return 'high'
        elif found_types.intersection(medium_types):
            return 'medium'
        elif ai_indicators:
            return 'low' 
        
        return 'info'

class SmartSearchEngine:
        
    def __init__(self, delay_range: tuple = (5.0, 12.0)):
        self.delay_range = delay_range
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
    
    def search_with_retry(self, query: str, num_results: int = 20) -> List[Dict]:
                
        search_strategies = [
            self._search_google_standard,
            self._search_google_alternative,
            self._search_bing_backup
        ]
        
        for strategy_name, strategy_func in [
            ("Google Standard", search_strategies[0]),
            ("Google Alternative", search_strategies[1]),
            ("Bing Backup", search_strategies[2])
        ]:
            try:
                print(f"    Checking {strategy_name}...")
                results = strategy_func(query, num_results)
                if results:
                    print(f"    ✓ {strategy_name}: {len(results)} results")
                    return results
                else:
                    print(f"    ✗ {strategy_name}: no results")
            except Exception as e:
                print(f"    ✗ {strategy_name}: Error - {e}")
                continue
        
        return []
    
    def _search_google_standard(self, query: str, num_results: int) -> List[Dict]:
        
        encoded_query = urllib.parse.quote_plus(query)
        url = f"https://www.google.com/search?q={encoded_query}&num={num_results}"
        
        return self._execute_search(url, query, 'google')
    
    def _search_google_alternative(self, query: str, num_results: int) -> List[Dict]:
        
        domains = ['www.google.co.uk', 'www.google.de', 'www.google.ca']
        
        for domain in domains:
            try:
                encoded_query = urllib.parse.quote_plus(query)
                url = f"https://{domain}/search?q={encoded_query}&num={num_results}"
                results = self._execute_search(url, query, f'google_{domain}')
                if results:
                    return results
            except:
                continue
        return []
    
    def _search_bing_backup(self, query: str, num_results: int) -> List[Dict]:
        
        encoded_query = urllib.parse.quote_plus(query)
        url = f"https://www.bing.com/search?q={encoded_query}&count={num_results}"
        
        return self._execute_search(url, query, 'bing')
    
    def _execute_search(self, url: str, query: str, source: str) -> List[Dict]:
        
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Cache-Control': 'no-cache'
        }
        
        response = self.session.get(url, headers=headers, timeout=15)
        
        if response.status_code == 429:
            raise Exception("Too Many Requests")
        elif response.status_code != 200:
            raise Exception(f"HTTP {response.status_code}")
        
        if source.startswith('google'):
            results = self._parse_google_results(response.text, query)
        elif source == 'bing':
            results = self._parse_bing_results(response.text, query)
        else:
            results = []
        
        delay = random.uniform(*self.delay_range)
        time.sleep(delay)
        
        return results
    
    def _parse_google_results(self, html: str, query: str) -> List[Dict]:
        
        soup = BeautifulSoup(html, 'html.parser')
        results = []
        
        result_selectors = [
            'div.g',
            'div[data-ved]',
            '.g',
            '.rc'
        ]
        
        for selector in result_selectors:
            elements = soup.select(selector)
            if elements:
                break
        
        for result in elements:
            try:
                
                title_elem = result.find('h3') or result.find('h2')
                if not title_elem:
                    continue
                
                link_elem = result.find('a')
                if not link_elem:
                    continue
                
                snippet_elem = result.find(['span', 'div'], class_=['VwiC3b', 'yXK7lf', 's', 'st'])
                
                title = title_elem.get_text().strip()
                url = link_elem.get('href', '')
                snippet = snippet_elem.get_text().strip() if snippet_elem else ""
                
                if url.startswith('/url?q='):
                    url = urllib.parse.parse_qs(
                        urllib.parse.urlparse(url).query
                    ).get('q', [''])[0]
                
                if url and url.startswith('http') and title:
                    results.append({
                        'title': title,
                        'url': url,
                        'snippet': snippet,
                        'query': query,
                        'source': 'google'
                    })
                    
            except Exception:
                continue
        
        return results
    
    def _parse_bing_results(self, html: str, query: str) -> List[Dict]:
        
        soup = BeautifulSoup(html, 'html.parser')
        results = []
        
        for result in soup.find_all('li', class_='b_algo'):
            try:
                title_elem = result.find('h2')
                link_elem = result.find('a')
                snippet_elem = result.find('p') or result.find('div', class_='b_caption')
                
                if title_elem and link_elem:
                    title = title_elem.get_text().strip()
                    url = link_elem.get('href', '')
                    snippet = snippet_elem.get_text().strip() if snippet_elem else ""
                    
                    if url.startswith('http'):
                        results.append({
                            'title': title,
                            'url': url,
                            'snippet': snippet,
                            'query': query,
                            'source': 'bing'
                        })
                        
            except Exception:
                continue
        
        return results

class AIDorkerV3:
       
    def __init__(self, delay_range: tuple = (5.0, 12.0), max_results: int = 20):
        self.search_engine = SmartSearchEngine(delay_range)
        self.analyzer = PreciseLeakAnalyzer()
        self.dorks = PreciseAIServiceDorks()
        self.max_results = max_results
        self.results = []
        
        self._init_database()
    
    def _init_database(self):
        
        with sqlite3.connect("ai_dorker_v3.db") as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS precise_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_id TEXT UNIQUE,
                    url TEXT,
                    title TEXT,
                    snippet TEXT,
                    service TEXT,
                    leak_type TEXT,
                    severity TEXT,
                    confidence_score REAL,
                    ai_indicators TEXT,
                    timestamp TEXT,
                    verified BOOLEAN DEFAULT 0
                )
            ''')
    
    def scan_all_services(self) -> List[LeakResult]:
        
        print("[INFO] 🔍 Launching accurate scanning of AI services v3.0...")
        all_dorks = self.dorks.get_all_dorks()
        
        total_processed = 0
        total_found = 0
        
        for i, (service, dork) in enumerate(all_dorks, 1):
            print(f"\n[{i}/{len(all_dorks)}] 🎯 {service.upper()}: {dork}")
            
            try:
                
                search_results = self.search_engine.search_with_retry(dork, self.max_results)
                total_processed += len(search_results)
                
                if not search_results:
                    print(f"  ⚠️  Results not Found")
                    continue
                
                print(f"  📊 Found {len(search_results)} results for analysis")
               
                service_findings = 0
                for j, result in enumerate(search_results, 1):
                    leak = self.analyzer.analyze_result(result, service)
                    if leak:
                        self.results.append(leak)
                        service_findings += 1
                        total_found += 1
                        
                        print(f"    [✓ {j}] {leak.severity.upper()}: {leak.url}")
                        print(f"         Confidence: {leak.confidence_score:.2f}")
                        print(f"         Type: {leak.leak_type}")
                        
                        self._save_leak_to_db(leak)
                
                if service_findings == 0:
                    print(f"  ❌ No real leaks found (analyzed {len(search_results)})")
                else:
                    print(f"  ✅ Found {service_findings} real leaks")
                    
            except Exception as e:
                print(f"  ❌ Scan error: {e}")
        
        print(f"\n📈 total: Processed {total_processed} results, found {total_found} real leaks")
        return self.results
    
    def _save_leak_to_db(self, leak: LeakResult):
        
        try:
            with sqlite3.connect("ai_dorker_v3.db") as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO precise_leaks 
                    (hash_id, url, title, snippet, service, leak_type, 
                     severity, confidence_score, ai_indicators, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    leak.hash_id, leak.url, leak.title, leak.snippet,
                    leak.service, leak.leak_type, leak.severity,
                    leak.confidence_score, json.dumps(leak.ai_chat_indicators),
                    leak.timestamp
                ))
        except Exception as e:
            print(f"[ERROR] Error saving to the database: {e}")
    
    def generate_precise_report(self):
        
        if not self.results:
            print("\n💡 RESULT: No real leaks from AI chats were found.")
            print("   This is a good sign - the services may have improved security!")
            return
        
        print("\n" + "="*80)
        print("                     🎯 AI DORKER v3.0 - ACCURATE REPORT")
        print("="*80)
        
        print(f"\n📊 ANALYSIS RESULTS:")
        print(f"   ✅ Confirmed leaks found: {len(self.results)}")
        print(f"   🕒 Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        services_stats = {}
        severity_stats = {}
        confidence_stats = {'high': 0, 'medium': 0, 'low': 0}
        
        for result in self.results:
            services_stats[result.service] = services_stats.get(result.service, 0) + 1
            severity_stats[result.severity] = severity_stats.get(result.severity, 0) + 1
            
            if result.confidence_score >= 0.7:
                confidence_stats['high'] += 1
            elif result.confidence_score >= 0.4:
                confidence_stats['medium'] += 1
            else:
                confidence_stats['low'] += 1
        
        print(f"\n🎯 DISTRIBUTION BY SERVICES:")
        for service, count in sorted(services_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"   {service.upper():15}: {count} утечка(и)")
        
        print(f"\n⚠️  CRITICALITY LEVELS:")
        severity_order = ['critical', 'high', 'medium', 'low']
        for severity in severity_order:
            count = severity_stats.get(severity, 0)
            if count > 0:
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
                print(f"   {emoji.get(severity, '⚪')} {severity.upper():10}: {count}")
        
        print(f"\n📊 CONFIDENCE IN RESULTS:")
        print(f"   🟢 High (≥70%): {confidence_stats['high']}")
        print(f"   🟡 Medium (40-69%): {confidence_stats['medium']}")
        print(f"   🔴 Low (<40%): {confidence_stats['low']}")
        
        critical_results = [r for r in self.results if r.severity in ['critical', 'high']]
        if critical_results:
            print(f"\n🚨 CRITICAL LEAKS (TOP 5):")
            for i, leak in enumerate(critical_results[:5], 1):
                print(f"\n   [{i}] {leak.service.upper()} - {leak.severity.upper()}")
                print(f"       🔗 URL: {leak.url}")
                print(f"       📋 Type leak: {leak.leak_type}")
                print(f"       📊 Confidence: {leak.confidence_score:.2f}")
                print(f"       🤖 AI-Indicators: {len(leak.ai_chat_indicators)}")
                if leak.snippet:
                    print(f"       📝 Snippet: {leak.snippet[:120]}...")

def main():
    
    banner()
    
    parser = argparse.ArgumentParser(
        description='AI Dorker v3.0 - accurate search for leaks in AI services'
    )
    parser.add_argument('-a', '--all', action='store_true', 
                       help='Scan all services')
    parser.add_argument('-s', '--service', 
                       help='Specific service (chatgpt, claude, etc.)')
    parser.add_argument('-d', '--delay', type=str, default='5-12',
                       help='Delay range in seconds (for example: 5-12)')
    parser.add_argument('-r', '--results', type=int, default=20,
                       help='Maximum results per request')
    parser.add_argument('-o', '--output', 
                       help='A file for saving JSON results')
    parser.add_argument('--list-services', action='store_true',
                       help='Show a list of available services')
    
    args = parser.parse_args()
    
    if args.list_services:
        print("🤖 Available AI services for scanning:")
        for service in PreciseAIServiceDorks.AI_SERVICES.keys():
            print(f"   • {service}")
        return
    
    try:
        if '-' in args.delay:
            delay_parts = args.delay.split('-')
            delay_range = (float(delay_parts[0]), float(delay_parts[1]))
        else:
            delay_val = float(args.delay)
            delay_range = (delay_val, delay_val + 3)
    except:
        delay_range = (5.0, 12.0)
        print("[WARNING] Incorrect delay format, default: 5-12 seconds")
    
    print(f"🕒 A delay is used: {delay_range[0]}-{delay_range[1]} second")
    
    dorker = AIDorkerV3(
        delay_range=delay_range,
        max_results=args.results
    )
    
    try:
        if args.all:
            dorker.scan_all_services()
        elif args.service:
            print(f"[INFO] Scanning the service {args.service} not implemented in v3.0 yet")
            print("       Use --all for a full scan.")
            return
        else:
            print("❓ Specify --all to scan all services.")
            print("  Or --list-services to view available services.")
            return
        
        dorker.generate_precise_report()
        
        if args.output and dorker.results:
            output_data = {
                'metadata': {
                    'version': '3.0',
                    'timestamp': datetime.now().isoformat(),
                    'total_found': len(dorker.results),
                    'delay_range': delay_range,
                    'max_results_per_query': args.results
                },
                'results': [asdict(result) for result in dorker.results]
            }
            
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n💾 The results are saved in: {args.output}")
            
    except KeyboardInterrupt:
        print(f"\n⚠️  The scan was interrupted by the user")
        if dorker.results:
            print(f"   Found before interruption: {len(dorker.results)} leaks")
            dorker.generate_precise_report()

if __name__ == "__main__":
    main()