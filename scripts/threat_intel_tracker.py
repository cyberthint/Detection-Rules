import requests
import json
import hashlib
import os
from datetime import datetime, timedelta
from pathlib import Path
import pickle
import logging
import re
import time
import zipfile
from collections import defaultdict

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatIntelCollector:
    def __init__(self):
        """Automatic Threat Intelligence Collector for Detection-Rules"""
        
        # GitHub token (from Actions)
        self.github_token = os.environ.get('GITHUB_TOKEN')
        
        # Telegram (from GitHub Secrets)
        self.telegram_token = os.environ.get('TELEGRAM_TOKEN')
        self.telegram_chat_id = os.environ.get('TELEGRAM_CHAT_ID')
        
        # OTX API (from GitHub Secrets)
        self.otx_key = os.environ.get('OTX_API_KEY')
        
        if not self.otx_key:
            logger.warning("⚠️ OTX_API_KEY not found! IOCs will not be collected.")
        
        # Data directories
        self.data_dir = Path("data")
        self.ioc_dir = Path("IOCs")
        self.yara_dir = Path("Yara")
        self.report_dir = Path("weekly_reports")
        self.archive_dir = Path("monthly_archives")
        self.scripts_dir = Path("scripts")
        
        # Create all directories
        for dir_path in [self.data_dir, self.ioc_dir, self.yara_dir, self.report_dir, self.archive_dir, self.scripts_dir]:
            dir_path.mkdir(exist_ok=True)
            logger.info(f"📁 Directory checked: {dir_path}")
        
        # Memory (already seen items)
        self.seen_iocs = self.load_data("seen_iocs.pkl", set())
        self.seen_yara = self.load_data("seen_yara.pkl", set())
        self.stats = self.load_data("stats.json", {
            'total_iocs': 0,
            'total_yara': 0,
            'by_source': defaultdict(int),
            'by_type': defaultdict(int),
            'last_update': None,
            'runs': 0
        })
        
        # YARA sources
        self.yara_sources = [
            {
                'name': 'Neo23x0 Signature Base',
                'url': 'https://github.com/Neo23x0/signature-base',
                'api_url': 'https://api.github.com/repos/Neo23x0/signature-base/contents/yara',
                'active': True
            },
            {
                'name': 'YARA-Rules Project',
                'url': 'https://github.com/Yara-Rules/rules',
                'api_url': 'https://api.github.com/repos/Yara-Rules/rules/contents/',
                'active': True
            },
            {
                'name': 'Intezer YARA',
                'url': 'https://github.com/intezer/yara-rules',
                'api_url': 'https://api.github.com/repos/intezer/yara-rules/contents/',
                'active': True
            },
            {
                'name': 'InQuest Awesome YARA',
                'url': 'https://github.com/InQuest/awesome-yara',
                'api_url': 'https://api.github.com/repos/InQuest/awesome-yara/contents/rules',
                'active': True
            },
            {
                'name': 'ESET Malware Research',
                'url': 'https://github.com/eset/malware-research',
                'api_url': 'https://api.github.com/repos/eset/malware-research/contents/yara',
                'active': True
            }
        ]
        
        logger.info("✅ Threat Intel Collector started")
        logger.info(f"📊 Memory: {len(self.seen_iocs)} IOCs, {len(self.seen_yara)} YARA rules")

    def send_telegram_message(self, message):
        """Send notification to Telegram"""
        if not self.telegram_token or not self.telegram_chat_id:
            logger.info("ℹ️ Telegram notification not sent (token or chat ID missing)")
            return

        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        
        try:
            response = requests.post(url, json=payload, timeout=15)
            if response.status_code == 200:
                logger.info("✅ Telegram notification sent")
            else:
                logger.error(f"❌ Telegram error: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Telegram connection error: {e}")
    
    def load_data(self, filename, default):
        """Load data from file"""
        filepath = self.data_dir / filename
        try:
            if filepath.exists():
                with open(filepath, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            logger.error(f"❌ Error loading data: {e}")
        return default
    
    def save_data(self, filename, data):
        """Save data to file"""
        filepath = self.data_dir / filename
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(data, f)
        except Exception as e:
            logger.error(f"❌ Error saving data: {e}")
    
    def calculate_hash(self, content):
        """Calculate hash for duplicate check"""
        return hashlib.sha256(str(content).encode()).hexdigest()
    
    def is_new_ioc(self, value, source):
        """Check if IOC is new"""
        hash_val = self.calculate_hash(f"{source}:{value}")
        if hash_val not in self.seen_iocs:
            self.seen_iocs.add(hash_val)
            self.stats['total_iocs'] += 1
            self.stats['by_source'][source] += 1
            return True
        return False
    
    def is_new_yara(self, name, content, source):
        """Check if YARA rule is new"""
        content_preview = content[:1000] if content else ""
        hash_val = self.calculate_hash(f"{source}:{name}:{content_preview}")
        if hash_val not in self.seen_yara:
            self.seen_yara.add(hash_val)
            self.stats['total_yara'] += 1
            self.stats['by_source'][f"{source}_YARA"] += 1
            return True
        return False
    
    def fetch_github_yara(self, source):
        """Fetch YARA rules from GitHub"""
        try:
            headers = {}
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            
            logger.info(f"🔍 Checking {source['name']}...")
            response = requests.get(source['api_url'], headers=headers, timeout=30)
            
            if response.status_code == 200:
                files = response.json()
                yara_files = []
                for f in files:
                    if isinstance(f, dict) and f.get('type') == 'file' and f['name'].endswith(('.yar', '.yara', '.rule')):
                        yara_files.append(f)
                
                logger.info(f"  📂 Found {len(yara_files)} YARA files")
                
                new_rules = []
                for file in yara_files[:50]:
                    try:
                        content_response = requests.get(file['download_url'], timeout=30)
                        if content_response.status_code == 200:
                            content = content_response.text
                            
                            if self.is_new_yara(file['name'], content, source['name']):
                                rule_info = {
                                    'source': source['name'],
                                    'name': file['name'],
                                    'content': content,
                                    'url': file['html_url'],
                                    'collected_at': datetime.now().isoformat()
                                }
                                new_rules.append(rule_info)
                                logger.info(f"  ✅ New: {file['name']}")
                    except Exception as e:
                        logger.error(f"  ❌ Error reading {file['name']}: {e}")
                
                logger.info(f"  📥 Found {len(new_rules)} new YARA rules")
                return new_rules
            else:
                logger.error(f"❌ {source['name']} error: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ Connection error to {source['name']}: {e}")
            return []
    
    def fetch_alienvault_iocs(self):
        """Fetch IOCs from AlienVault OTX"""
        try:
            if not self.otx_key:
                logger.warning("⚠️ OTX API key missing, skipping IOC collection")
                return []
            
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            headers = {"X-OTX-API-KEY": self.otx_key}
            params = {"limit": 10, "page": 1}
            
            logger.info("🔍 Checking AlienVault OTX...")
            response = requests.get(url, headers=headers, params=params, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('results', [])
                logger.info(f"  📂 Found {len(pulses)} pulses")
                
                new_iocs = []
                for pulse in pulses:
                    indicators = pulse.get('indicators', [])
                    for ioc in indicators[:5]:
                        ioc_value = ioc.get('indicator')
                        ioc_type = ioc.get('type', 'unknown')
                        
                        if ioc_value and self.is_new_ioc(ioc_value, 'AlienVault'):
                            ioc_info = {
                                'source': 'AlienVault OTX',
                                'pulse': pulse.get('name', 'Unknown'),
                                'type': ioc_type,
                                'value': ioc_value,
                                'description': pulse.get('description', '')[:200],
                                'tags': pulse.get('tags', []),
                                'created': pulse.get('created'),
                                'reference': f"https://otx.alienvault.com/pulse/{pulse.get('id')}"
                            }
                            new_iocs.append(ioc_info)
                
                logger.info(f"  📥 Found {len(new_iocs)} new IOCs")
                return new_iocs
            else:
                logger.error(f"❌ AlienVault error: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ AlienVault connection error: {e}")
            return []
    
    def save_yara_rules(self, rules):
        """Save YARA rules to daily folder"""
        if not rules:
            return []
        
        today = datetime.now().strftime('%Y-%m-%d')
        today_dir = self.yara_dir / today
        today_dir.mkdir(exist_ok=True)
        
        saved_files = []
        for rule in rules:
            try:
                safe_name = re.sub(r'[^\w\-_\.]', '_', rule['name'])
                if len(safe_name) > 100:
                    name_part = safe_name[:50]
                    hash_part = self.calculate_hash(safe_name)[:8]
                    safe_name = f"{name_part}_{hash_part}.yar"
                elif not safe_name.endswith(('.yar', '.yara')):
                    safe_name += '.yar'
                
                filepath = today_dir / safe_name
                
                header = f"""// ════════════════════════════════════════════════════════
// Source     : {rule['source']}
// Rule       : {rule['name']}
// Collected  : {rule['collected_at']}
// Original   : {rule['url']}
// ════════════════════════════════════════════════════════

"""
                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(header + rule['content'])
                
                saved_files.append(str(filepath))
                logger.info(f"  💾 Saved: {filepath}")
            except Exception as e:
                logger.error(f"  ❌ Error saving {rule['name']}: {e}")
        
        return saved_files
    
    def save_iocs(self, iocs):
        """Save IOCs to daily folder"""
        if not iocs:
            return []
        
        today = datetime.now().strftime('%Y-%m-%d')
        today_dir = self.ioc_dir / today
        today_dir.mkdir(exist_ok=True)
        
        saved_files = []
        for ioc in iocs:
            try:
                ioc_type = ioc['type'].lower().replace(' ', '_')
                ioc_hash = self.calculate_hash(ioc['value'])[:8]
                filename = f"{ioc_type}_{ioc_hash}.json"
                filepath = today_dir / filename
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(ioc, f, indent=2, ensure_ascii=False)
                
                saved_files.append(str(filepath))
            except Exception as e:
                logger.error(f"  ❌ Error saving IOC: {e}")
        
        logger.info(f"  💾 Saved {len(saved_files)} IOCs")
        return saved_files
    
    def create_weekly_report(self):
        """Create weekly report"""
        today = datetime.now()
        
        if today.weekday() == 0:
            week_num = today.strftime('%W')
            year = today.strftime('%Y')
            
            report_file = self.report_dir / f"week-{week_num}-{year}.md"
            
            week_iocs = 0
            week_yara = 0
            
            for i in range(7):
                date = (today - timedelta(days=i)).strftime('%Y-%m-%d')
                ioc_day_dir = self.ioc_dir / date
                yara_day_dir = self.yara_dir / date
                
                if ioc_day_dir.exists():
                    week_iocs += len(list(ioc_day_dir.glob("*.json")))
                if yara_day_dir.exists():
                    week_yara += len(list(yara_day_dir.glob("*.yar*")))
            
            report = "# 📊 Weekly Threat Intelligence Report\n"
            report += f"**Week:** {week_num} - {year}\n"
            report += f"**Date:** {today.strftime('%d.%m.%Y')}\n\n"
            report += "## 📈 Summary Statistics\n"
            report += f"- **Total IOCs:** {self.stats['total_iocs']}\n"
            report += f"- **Total YARA Rules:** {self.stats['total_yara']}\n"
            report += f"- **Added This Week:** {week_iocs} IOCs, {week_yara} YARA\n"
            report += f"- **Total Runs:** {self.stats['runs']}\n\n"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            
            logger.info(f"📊 Weekly report created: {report_file}")
    
    def create_monthly_archive(self):
        """Create monthly archive"""
        today = datetime.now()
        
        if today.day == 1:
            last_month = today - timedelta(days=1)
            month = last_month.strftime('%Y-%m')
            
            archive_name = self.archive_dir / f"{month}.zip"
            
            with zipfile.ZipFile(archive_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                files_added = 0
                for i in range(30):
                    date = (today - timedelta(days=i+1)).strftime('%Y-%m-%d')
                    if date.startswith(month):
                        ioc_day_dir = self.ioc_dir / date
                        yara_day_dir = self.yara_dir / date
                        
                        if ioc_day_dir.exists():
                            for file in ioc_day_dir.glob("*"):
                                zipf.write(file, f"IOCs/{date}/{file.name}")
                                files_added += 1
                        
                        if yara_day_dir.exists():
                            for file in yara_day_dir.glob("*"):
                                zipf.write(file, f"Yara/{date}/{file.name}")
                                files_added += 1
                
                if files_added > 0:
                    logger.info(f"📦 Monthly archive created: {archive_name} ({files_added} files)")
                else:
                    logger.info(f"📦 No files to archive for {month}")
    
    def update_readme(self):
        """Automatically update README.md (English)"""
        try:
            week_iocs = 0
            week_yara = 0
            today = datetime.now()
            
            for i in range(7):
                date = (today - timedelta(days=i)).strftime('%Y-%m-%d')
                ioc_day_dir = self.ioc_dir / date
                yara_day_dir = self.yara_dir / date
                
                if ioc_day_dir.exists():
                    week_iocs += len(list(ioc_day_dir.glob("*.json")))
                if yara_day_dir.exists():
                    week_yara += len(list(yara_day_dir.glob("*.yar*")))
            
            yara_sources_list = ""
            for source in self.yara_sources:
                if source.get('active', True):
                    yara_sources_list += f"- [{source['name']}]({source['url']})\n"
            
            readme_content = f"""# 🛡️ Detection Rules

This repository is **automatically updated** every 6 hours with the latest YARA rules and IOCs (Indicators of Compromise).

## 📊 Current Statistics
- **Total IOCs:** {self.stats['total_iocs']}
- **Total YARA Rules:** {self.stats['total_yara']}
- **Last 7 Days:** +{week_iocs} IOCs, +{week_yara} YARA
- **Last Update:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Total Runs:** {self.stats['runs']}

## 🤖 Automatic Updates
| Type | Frequency |
|------|-----------|
| YARA Rules | Every 6 hours |
| IOCs | Every 6 hours |
| Weekly Reports | Every Monday |
| Monthly Archives | 1st day of month |


## 📞 Contact
**cyberthint Team**

---
*Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
            with open("README.md", "w", encoding="utf-8") as f:
                f.write(readme_content)
                
            logger.info("✅ README.md updated successfully")
        except Exception as e:
            logger.error(f"❌ README update error: {e}")

    def run(self):
        """Main collection process"""
        start_time = time.time()
        logger.info("="*60)
        logger.info("🚀 Detection-Rules Collection Process Started...")
        logger.info(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        self.stats['runs'] += 1
        new_iocs_count = 0
        new_yara_count = 0
        
        logger.info("\n📥 COLLECTING IOCs...")
        iocs = self.fetch_alienvault_iocs()
        if iocs:
            saved_iocs = self.save_iocs(iocs)
            new_iocs_count = len(saved_iocs)
        
        logger.info("\n📥 COLLECTING YARA RULES...")
        for source in self.yara_sources:
            if source.get('active', True):
                rules = self.fetch_github_yara(source)
                if rules:
                    saved_rules = self.save_yara_rules(rules)
                    new_yara_count += len(saved_rules)
        
        self.stats['last_update'] = datetime.now().isoformat()
        self.save_data("stats.json", self.stats)
        self.save_data("seen_iocs.pkl", self.seen_iocs)
        self.save_data("seen_yara.pkl", self.seen_yara)
        
        logger.info("\n📊 GENERATING REPORTS...")
        self.create_weekly_report()
        self.create_monthly_archive()
        self.update_readme()
        
        if new_iocs_count > 0 or new_yara_count > 0:
            summary_msg = (
                f"🤖 <b>Detection-Rules Updated</b>\n\n"
                f"📥 <b>New Additions:</b>\n"
                f"🔸 New IOCs: <b>{new_iocs_count}</b>\n"
                f"🔸 New YARA: <b>{new_yara_count}</b>\n\n"
                f"📊 <b>Total:</b>\n"
                f"🔹 Total IOCs: {self.stats['total_iocs']}\n"
                f"🔹 Total YARA: {self.stats['total_yara']}\n\n"
                f"🔗 https://github.com/cyberthint/Detection-Rules"
            )
            self.send_telegram_message(summary_msg)
        else:
            self.send_telegram_message("🤖 <b>Detection-Rules Check</b>\n\n📭 No new IOCs or YARA rules found.")
        
        elapsed_time = time.time() - start_time
        logger.info(f"\n{'='*60}")
        logger.info(f"✅ PROCESS COMPLETED - New IOCs: {new_iocs_count}, New YARA: {new_yara_count}")
        logger.info(f"📊 Total: {self.stats['total_iocs']} IOCs, {self.stats['total_yara']} YARA")
        logger.info(f"⏱️ Time: {elapsed_time:.2f} seconds")
        logger.info(f"{'='*60}")

if __name__ == "__main__":
    collector = ThreatIntelCollector()
    collector.run()