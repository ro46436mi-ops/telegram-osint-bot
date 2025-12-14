# Telegram OSINT Bot - Discord Style Structure

A feature-rich Telegram bot for OSINT and cyber tools, structured like a Discord bot with cogs and utils folders.

## 📁 Project Structure
```

telegram-osint-bot/
├──app.py                    # Main entry point
├──requirements.txt          # Dependencies
├──.gitignore               # Git ignore
├──README.md                # Documentation
├──render.yaml              # Render deployment config
├──cogs/                    # Discord-style cogs
│├── init.py
│└── cyber_tools.py       # Main bot logic
├──utils/                   # Utilities
│├── init.py
│└── api_handler.py       # API management
└──data/                    # Data storage
└── logs/                # Logs directory

```

## 🚀 Features
- **IP Lookup**: Geolocation and ISP information
- **Phone Lookup**: Carrier, country, line type
- **Email Breach Check**: Have I Been Pwned integration
- **WHOIS Lookup**: Domain registration information
- **Reverse Image Search**: Google reverse image
- **Hash Cracker**: MD5, SHA1, SHA256 (common passwords)
- **Username Search**: Check 50+ platforms
- **Google Dorks**: Security testing dorks
- **Base64 Tools**: Encode/decode
- **QR Generator**: Create QR codes

## 🔧 Required APIs
1. **IPInfo.io** - IP geolocation
2. **NumVerify** - Phone number validation
3. **WhoisFreaks** - Domain WHOIS lookup
4. **SerpAPI** - Reverse image search
5. **Have I Been Pwned** - Email breach check (no API key needed)

## ⚙️ Environment Variables
Set these in Render.com environment:
```

TELEGRAM_BOT_TOKEN=your_telegram_bot_token
IPINFO_TOKEN=your_ipinfo_token
NUMVERIFY_KEY=your_numverify_key
WHOISFREAKS_KEY=your_whoisfreaks_key
SERPAPI_KEY=your_serpapi_key
HIBP_USER_AGENT=Telegram-OSINT-Bot/1.0

```

## 🤖 Commands
- `/start` - Start bot and show menu
- `/help` - Show all commands
- `/ip <address>` - IP lookup
- `/phone <number>` - Phone lookup
- `/email <address>` - Email breach check
- `/whois <domain>` - WHOIS lookup
- `/reverse <image_url>` - Reverse image search
- `/hash <type> <hash>` - Hash cracker
- `/user <username>` - Username search
- `/dorks <domain>` - Google dorks
- `/base64 <encode/decode> <text>` - Base64 tools
- `/qr <text>` - QR generator
- `/apis` - Check API status

## ☁️ Render Deployment
1. Push code to GitHub repository
2. Create new Background Worker on Render
3. Connect GitHub repository
4. Set environment variables
5. Deploy!

## ⚠️ Legal Disclaimer
This bot is for educational and ethical security testing only. Use responsibly and only on systems you own or have permission to test.

## 📄 License
MIT License - See LICENSE file for details
```

---

🚀 DEPLOYMENT STEPS:

1. Create all 9 files:

· app.py
· requirements.txt
· .gitignore
· README.md
· render.yaml
· cogs/__init__.py
· cogs/cyber_tools.py
· utils/__init__.py
· utils/api_handler.py

2. Create directory structure:

```bash
mkdir telegram-osint-bot
cd telegram-osint-bot
mkdir -p cogs utils data/logs
```

3. GitHub push:

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/yourusername/telegram-osint-bot.git
git push -u origin main
```

4. Render deployment:

1. Go to render.com
2. Create New Background Worker
3. Connect GitHub repository
4. Add Environment Variables:
   · TELEGRAM_BOT_TOKEN = your_bot_token
   · IPINFO_TOKEN = 02db5102114779
   · NUMVERIFY_KEY = 304e4bbe12a87a1537050a4decc6a4a2
   · WHOISFREAKS_KEY = 93eb1310d9884e668510fb7b6f55b292
   · SERPAPI_KEY = ca644f2d9e6b588a09706351c00eff5ad8f8e2e4334a82832497a5c07b0d7e64
   · HIBP_USER_AGENT = Telegram-OSINT-Bot/1.0

5. Test bot:

Open Telegram, search your bot, send:

· /start - See main menu
· /ip 8.8.8.8 - Test IP lookup
· /apis - Check API status
