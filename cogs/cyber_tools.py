"""
Main bot commands - Discord cog style
"""
import os
import io
import json
import base64
import hashlib
import urllib.parse
import qrcode
from datetime import datetime
from typing import Dict, Any

from telegram import (
    Update, 
    InlineKeyboardButton, 
    InlineKeyboardMarkup,
    BotCommand
)
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)

from utils.api_handler import api_handler

class CyberToolsBot:
    """Main bot class - Discord bot structure"""
    
    def __init__(self, token: str):
        self.token = token
        self.application = None
        self.commands = [
            ("start", "Start the bot"),
            ("help", "Show help information"),
            ("ip", "IP lookup - /ip 8.8.8.8"),
            ("phone", "Phone lookup - /phone +919876543210"),
            ("email", "Email breach check - /email test@example.com"),
            ("whois", "WHOIS lookup - /whois google.com"),
            ("reverse", "Reverse image search - /reverse image_url"),
            ("hash", "Hash cracker - /hash md5 5d41402abc4b2a76b9719d911017c592"),
            ("user", "Username search - /user username"),
            ("dorks", "Google dorks - /dorks example.com"),
            ("base64", "Base64 encode/decode - /base64 encode hello"),
            ("qr", "QR generator - /qr https://example.com"),
            ("apis", "Check API status"),
        ]
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler for /start command"""
        user = update.effective_user
        
        # Check API status
        api_status = api_handler.check_api_status()
        
        # Build status message
        status_msg = "✅ **Available APIs:**\n"
        for api, available in api_status.items():
            status_msg += f"• {api.upper()}: {'✅' if available else '❌'}\n"
        
        welcome_text = f"""
🎯 **Telegram OSINT Bot** - Cyber Tools Collection

👋 Welcome **{user.first_name}**!

**Available Features:**
• IP Lookup & Geolocation
• Phone Number Information
• Email Breach Check
• WHOIS Domain Lookup
• Reverse Image Search
• Hash Cracking
• Username Search
• Google Dorks Generator
• Base64 Encode/Decode
• QR Code Generator

{status_msg}
**Commands:**
Use `/help` to see all commands
Use `/apis` to check API status

**Note:** Some features require API keys set in environment
        """
        
        # Main menu buttons
        keyboard = [
            [
                InlineKeyboardButton("🌐 IP Tools", callback_data="ip_tools"),
                InlineKeyboardButton("📱 Phone Tools", callback_data="phone_tools")
            ],
            [
                InlineKeyboardButton("📧 Email Tools", callback_data="email_tools"),
                InlineKeyboardButton("🔍 OSINT Tools", callback_data="osint_tools")
            ],
            [
                InlineKeyboardButton("🛠️ Utilities", callback_data="utility_tools"),
                InlineKeyboardButton("❓ Help", callback_data="help_menu")
            ]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            welcome_text,
            reply_markup=reply_markup,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler for /help command"""
        help_text = "**📚 Available Commands:**\n\n"
        
        for cmd, desc in self.commands:
            help_text += f"`/{cmd}` - {desc}\n"
        
        help_text += "\n**Usage Examples:**\n"
        help_text += "• `/ip 8.8.8.8` - Lookup IP information\n"
        help_text += "• `/phone +919876543210` - Phone number lookup\n"
        help_text += "• `/email test@example.com` - Check email breaches\n"
        help_text += "• `/whois google.com` - Domain WHOIS lookup\n"
        help_text += "• `/hash md5 5d41402abc4b2a76b9719d911017c592` - Crack hash\n"
        help_text += "• `/user john` - Search username across platforms\n"
        
        await update.message.reply_text(
            help_text,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )
    
    async def ip_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler for /ip command"""
        if not context.args:
            await update.message.reply_text(
                "❌ **Usage:** `/ip <ip_address>`\n"
                "**Example:** `/ip 8.8.8.8` or `/ip 1.1.1.1`",
                parse_mode="Markdown"
            )
            return
        
        ip_address = context.args[0]
        
        # Validate IP format (basic)
        if not self._is_valid_ip(ip_address):
            await update.message.reply_text(
                "❌ **Invalid IP address format!**\n"
                "Please enter a valid IPv4 or IPv6 address.",
                parse_mode="Markdown"
            )
            return
        
        await update.message.reply_text(f"🔍 Looking up IP: `{ip_address}`...", parse_mode="Markdown")
        
        # Call API
        result = api_handler.ip_lookup(ip_address)
        
        if "error" in result:
            await update.message.reply_text(
                f"❌ **Error:** {result['error']}",
                parse_mode="Markdown"
            )
            return
        
        # Format response
        response_text = f"""
🌐 **IP Lookup Results**

**IP Address:** `{result.get('ip', 'N/A')}`
**Hostname:** `{result.get('hostname', 'N/A')}`
**City:** {result.get('city', 'N/A')}
**Region:** {result.get('region', 'N/A')}
**Country:** {result.get('country', 'N/A')} ({result.get('country_name', 'N/A')})
**Location:** {result.get('loc', 'N/A')}
**ISP:** {result.get('org', 'N/A')}
**Postal Code:** {result.get('postal', 'N/A')}
**Timezone:** {result.get('timezone', 'N/A')}
"""
        
        await update.message.reply_text(
            response_text,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )
    
    async def phone_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler for /phone command"""
        if not context.args:
            await update.message.reply_text(
                "❌ **Usage:** `/phone <phone_number>`\n"
                "**Example:** `/phone +919876543210` or `/phone 9876543210`",
                parse_mode="Markdown"
            )
            return
        
        phone_number = context.args[0]
        
        await update.message.reply_text(f"📱 Looking up phone: `{phone_number}`...", parse_mode="Markdown")
        
        # Call API
        result = api_handler.phone_lookup(phone_number)
        
        if "error" in result:
            await update.message.reply_text(
                f"❌ **Error:** {result['error']}",
                parse_mode="Markdown"
            )
            return
        
        if not result.get('valid'):
            await update.message.reply_text(
                "❌ **Invalid phone number!**",
                parse_mode="Markdown"
            )
            return
        
        # Format response
        response_text = f"""
📞 **Phone Lookup Results**

**Number:** `{result.get('number', 'N/A')}`
**Valid:** {'✅ Yes' if result.get('valid') else '❌ No'}
**Local Format:** {result.get('local_format', 'N/A')}
**International Format:** {result.get('international_format', 'N/A')}
**Country:** {result.get('country_name', 'N/A')} ({result.get('country_code', 'N/A')})
**Location:** {result.get('location', 'N/A')}
**Carrier:** {result.get('carrier', 'N/A')}
**Line Type:** {result.get('line_type', 'N/A')}
"""
        
        await update.message.reply_text(
            response_text,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )
    
    async def email_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler for /email command"""
        if not context.args:
            await update.message.reply_text(
                "❌ **Usage:** `/email <email_address>`\n"
                "**Example:** `/email test@example.com`",
                parse_mode="Markdown"
            )
            return
        
        email = context.args[0]
        
        # Basic email validation
        if '@' not in email or '.' not in email:
            await update.message.reply_text(
                "❌ **Invalid email format!**",
                parse_mode="Markdown"
            )
            return
        
        await update.message.reply_text(f"📧 Checking email: `{email}`...", parse_mode="Markdown")
        
        # Call API
        result = api_handler.email_breach_check(email)
        
        if "error" in result:
            await update.message.reply_text(
                f"❌ **Error:** {result['error']}",
                parse_mode="Markdown"
            )
            return
        
        if result.get('safe'):
            response_text = f"""
✅ **Email Security Check**

**Email:** `{email}`
**Status:** 🔒 **Safe - No breaches found!**
**Message:** This email was not found in any known data breaches.
"""
        else:
            breaches = result.get('breaches', [])
            breach_list = "\n".join([f"• {b.get('Name', 'Unknown')} ({b.get('BreachDate', 'Unknown date')})" 
                                   for b in breaches[:3]])  # Show first 3 breaches
            
            response_text = f"""
⚠️ **Email Security Alert!**

**Email:** `{email}`
**Status:** 🔓 **Compromised in {result.get('count', 0)} breaches!**
**Breaches Found:**
{breach_list}

**Recommendation:**
1. Change your password immediately
2. Enable two-factor authentication
3. Use a password manager
"""
            
            if result.get('count', 0) > 3:
                response_text += f"\n*... and {result.get('count', 0) - 3} more breaches*"
        
        await update.message.reply_text(
            response_text,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )
    
    async def whois_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler for /whois command"""
        if not context.args:
            await update.message.reply_text(
                "❌ **Usage:** `/whois <domain>`\n"
                "**Example:** `/whois google.com` or `/whois github.com`",
                parse_mode="Markdown"
            )
            return
        
        domain = context.args[0].lower()
        
        # Add .com if not present
        if '.' not in domain:
            domain = f"{domain}.com"
        
        await update.message.reply_text(f"🔍 Looking up domain: `{domain}`...", parse_mode="Markdown")
        
        # Call API
        result = api_handler.whois_lookup(domain)
        
        if "error" in result:
            await update.message.reply_text(
                f"❌ **Error:** {result['error']}",
                parse_mode="Markdown"
            )
            return
        
        # Format response
        whois_data = result.get('whois_domain_data', {})
        
        response_text = f"""
🌐 **WHOIS Lookup Results**

**Domain:** `{whois_data.get('domain_name', 'N/A')}`
**Registered:** {whois_data.get('create_date', 'N/A')}
**Expires:** {whois_data.get('expiry_date', 'N/A')}
**Updated:** {whois_data.get('updated_date', 'N/A')}
**Status:** {whois_data.get('domain_status', 'N/A')}

**Registrar:**
**Name:** {whois_data.get('registrar', 'N/A')}
**URL:** {whois_data.get('registrar_url', 'N/A')}

**Name Servers:**
"""
        
        # Add name servers
        name_servers = whois_data.get('name_servers', [])
        if isinstance(name_servers, list):
            for ns in name_servers[:3]:  # Show first 3
                response_text += f"• `{ns}`\n"
        
        response_text += f"\n**WHOIS Server:** {whois_data.get('whois_server', 'N/A')}"
        
        await update.message.reply_text(
            response_text,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )
    
    async def reverse_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler for /reverse command"""
        if not context.args:
            await update.message.reply_text(
                "❌ **Usage:** `/reverse <image_url>`\n"
                "**Example:** `/reverse https://example.com/image.jpg`",
                parse_mode="Markdown"
            )
            return
        
        image_url = context.args[0]
        
        # Validate URL
        if not (image_url.startswith('http://') or image_url.startswith('https://')):
            await update.message.reply_text(
                "❌ **Invalid URL!** Must start with http:// or https://",
                parse_mode="Markdown"
            )
            return
        
        await update.message.reply_text(f"🔍 Reverse searching image...", parse_mode="Markdown")
        
        # Call API
        result = api_handler.reverse_image_search(image_url)
        
        if "error" in result:
            await update.message.reply_text(
                f"❌ **Error:** {result['error']}",
                parse_mode="Markdown"
            )
            return
        
        # Format response
        response_text = "🔍 **Reverse Image Search Results**\n\n"
        
        # Check for inline_images
        inline_images = result.get('inline_images', [])
        
        if inline_images:
            response_text += f"Found {len(inline_images)} similar images\n\n"
            
            # Show first 3 results
            for i, img in enumerate(inline_images[:3], 1):
                title = img.get('title', 'No title')
                source = img.get('source', 'Unknown source')
                link = img.get('link', '#')
                
                response_text += f"**{i}. {title}**\n"
                response_text += f"Source: {source}\n"
                response_text += f"Link: {link}\n\n"
        else:
            response_text += "No similar images found."
        
        await update.message.reply_text(
            response_text,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )
    
    async def hash_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler for /hash command"""
        if len(context.args) < 2:
            await update.message.reply_text(
                "❌ **Usage:** `/hash <type> <hash_value>`\n"
                "**Types:** md5, sha1, sha256\n"
                "**Example:** `/hash md5 5d41402abc4b2a76b9719d911017c592`",
                parse_mode="Markdown"
            )
            return
        
        hash_type = context.args[0].lower()
        hash_value = context.args[1].lower()
        
        # Validate hash type
        valid_types = ['md5', 'sha1', 'sha256']
        if hash_type not in valid_types:
            await update.message.reply_text(
                f"❌ **Invalid hash type!**\n"
                f"Valid types: {', '.join(valid_types)}",
                parse_mode="Markdown"
            )
            return
        
        # Validate hash length
        expected_lengths = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64
        }
        
        if len(hash_value) != expected_lengths[hash_type]:
            await update.message.reply_text(
                f"❌ **Invalid {hash_type.upper()} hash!**\n"
                f"Expected {expected_lengths[hash_type]} characters, got {len(hash_value)}",
                parse_mode="Markdown"
            )
            return
        
        await update.message.reply_text(
            f"🔓 Attempting to crack {hash_type.upper()} hash...\n"
            f"Hash: `{hash_value}`",
            parse_mode="Markdown"
        )
        
        # Try common passwords
        common_passwords = [
            'password', '123456', '12345678', '1234', 'qwerty',
            '12345', 'dragon', 'baseball', 'football', 'letmein',
            'monkey', '696969', 'abc123', 'mustang', 'michael',
            'shadow', 'master', 'jennifer', '111111', '2000',
            'jordan', 'superman', 'harley', '1234567', 'fuckme',
            'hunter', 'fuckyou', 'trustno1', 'ranger', 'buster',
            'thomas', 'tigger', 'robert', 'soccer', 'batman',
            'test', 'pass', 'killer', 'hockey', 'george'
        ]
        
        # Check against common passwords
        for password in common_passwords:
            if hash_type == 'md5':
                test_hash = hashlib.md5(password.encode()).hexdigest()
            elif hash_type == 'sha1':
                test_hash = hashlib.sha1(password.encode()).hexdigest()
            elif hash_type == 'sha256':
                test_hash = hashlib.sha256(password.encode()).hexdigest()
            else:
                test_hash = ''
            
            if test_hash == hash_value:
                response_text = f"""
✅ **Hash Cracked Successfully!**

**Hash Type:** {hash_type.upper()}
**Hash Value:** `{hash_value}`
**Plaintext:** `{password}`
**Status:** 🔓 **CRACKED**
"""
                await update.message.reply_text(response_text, parse_mode="Markdown")
                return
        
        # If not found in common passwords
        response_text = f"""
❌ **Hash Not Cracked**

**Hash Type:** {hash_type.upper()}
**Hash Value:** `{hash_value}`
**Status:** 🔒 **NOT FOUND in common passwords**

**Suggestions:**
1. Try more extensive wordlists
2. Use GPU-based cracking tools
3. Check if it's a salted hash
4. Try online hash databases
"""
        
        await update.message.reply_text(response_text, parse_mode="Markdown")
    
    async def user_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler for /user command"""
        if not context.args:
            await update.message.reply_text(
                "❌ **Usage:** `/user <username>`\n"
                "**Example:** `/user john` or `/user johndoe123`",
                parse_mode="Markdown"
            )
            return
        
        username = context.args[0]
        
        await update.message.reply_text(
            f"🔍 Searching for username: `{username}`\n"
            f"This may take a moment...",
            parse_mode="Markdown"
        )
        
        # Common social media platforms (simulated search)
        platforms = [
            {"name": "GitHub", "url": f"https://github.com/{username}", "icon": "💻"},
            {"name": "Twitter", "url": f"https://twitter.com/{username}", "icon": "🐦"},
            {"name": "Instagram", "url": f"https://instagram.com/{username}", "icon": "📷"},
            {"name": "Facebook", "url": f"https://facebook.com/{username}", "icon": "👤"},
            {"name": "Reddit", "url": f"https://reddit.com/user/{username}", "icon": "📰"},
            {"name": "YouTube", "url": f"https://youtube.com/@{username}", "icon": "📺"},
            {"name": "LinkedIn", "url": f"https://linkedin.com/in/{username}", "icon": "💼"},
            {"name": "Twitch", "url": f"https://twitch.tv/{username}", "icon": "🎮"},
        ]
        
        response_text = f"""
🔍 **Username Search Results**

**Username:** `{username}`

**Checking platforms:**
"""
        
        for platform in platforms:
            response_text += f"{platform['icon']} {platform['name']}: {platform['url']}\n"
        
        response_text += "\n**Note:** This checks common URL patterns. Actual existence may vary."
        
        await update.message.reply_text(
            response_text,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )
    
    async def dorks_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler for /dorks command"""
        if not context.args:
            await update.message.reply_text(
                "❌ **Usage:** `/dorks <domain>`\n"
                "**Example:** `/dorks example.com`",
                parse_mode="Markdown"
            )
            return
        
        domain = context.args[0]
        
        # Generate Google dorks
        dorks = [
            f"site:{domain} filetype:pdf",
            f"site:{domain} filetype:doc OR filetype:docx",
            f"site:{domain} filetype:xls OR filetype:xlsx",
            f"site:{domain} inurl:admin",
            f"site:{domain} inurl:login",
            f"site:{domain} intitle:\"index of\"",
            f"site:{domain} \"password\"",
            f"site:{domain} \"username\" OR \"user\"",
            f"site:{domain} intext:\"confidential\"",
            f"site:{domain} \"api_key\" OR \"apikey\"",
            f"site:{domain} \"secret\"",
            f"site:{domain} \"backup\"",
            f"site:{domain} \"debug\" OR \"testing\"",
            f"site:{domain} ext:sql",
            f"site:{domain} ext:env",
            f"site:{domain} ext:log",
            f"site:{domain} ext:txt \"password\"",
        ]
        
        response_text = f"""
🔍 **Google Dorks for {domain}**

**Use these in Google search:**
"""
      # Add dorks
for i, dork in enumerate(dorks[:15], 1):  # Show first 15
    response_text += f"{dork}\n"

response_text += """```

"""

Tips:

1. Copy and paste into Google
2. Add more specific keywords
3. Use quotes for exact phrases
4. Combine multiple dorks with OR

Note: Use responsibly and ethically!
"""
        await update.message.reply_text(
        response_text,
        parse_mode="Markdown"
    )

async def base64_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for /base64 command"""
    if len(context.args) < 2:
        await update.message.reply_text(
            "❌ **Usage:** `/base64 <encode|decode> <text>`\n"
            "**Example:** `/base64 encode hello`\n"
            "**Example:** `/base64 decode aGVsbG8=`",
            parse_mode="Markdown"
        )
        return
    
    action = context.args[0].lower()
    text = ' '.join(context.args[1:])
    
    if action not in ['encode', 'decode']:
        await update.message.reply_text(
            "❌ **Invalid action!** Use 'encode' or 'decode'",
            parse_mode="Markdown"
        )
        return
    
    try:
        if action == 'encode':
            # Encode to base64
            encoded = base64.b64encode(text.encode()).decode()
            response_text = f"""
            🔢Base64 Decoding

Encoded: {text}
Decoded:{decoded}

Usage: echo '{text}' | base64 -d
"""
        await update.message.reply_text(response_text, parse_mode="Markdown")
        
    except Exception as e:
        await update.message.reply_text(
            f"❌ **Error:** {str(e)}",
            parse_mode="Markdown"
        )

async def qr_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for /qr command"""
    if not context.args:
        await update.message.reply_text(
            "❌ **Usage:** `/qr <text_or_url>`\n"
            "**Example:** `/qr https://example.com`\n"
            "**Example:** `/qr Hello World!`",
            parse_mode="Markdown"
        )
        return
    
    text = ' '.join(context.args)
    
    try:
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        
        # Send QR code
        caption = f"""

        📱 QR Code Generated

Content: {text[:50]}{'...' if len(text) > 50 else ''}

Scan this QR code with your phone camera or QR scanner app.
"""
        await update.message.reply_photo(
            photo=img_bytes,
            caption=caption,
            parse_mode="Markdown"
        )
        
    except Exception as e:
        await update.message.reply_text(
            f"❌ **Error generating QR:** {str(e)}",
            parse_mode="Markdown"
        )

async def apis_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for /apis command - Check API status"""
    api_status = api_handler.check_api_status()
    
    response_text = "🔧 **API Status Check**\n\n"
    
    for api, available in api_status.items():
        status = "✅ Available" if available else "❌ Not Configured"
        response_text += f"• **{api.upper()}:** {status}\n"
    
    response_text += "\n**Configuration:**\n"
    response_text += "Set API keys as environment variables:\n"
    response_text += "`IPINFO_TOKEN`, `NUMVERIFY_KEY`, `WHOISFREAKS_KEY`, `SERPAPI_KEY`"
    
    await update.message.reply_text(
        response_text,
        parse_mode="Markdown"
    )

async def button_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline button clicks"""
    query = update.callback_query
    await query.answer()
    
    data = query.data
    
    if data == "ip_tools":
        await query.edit_message_text(
            "🌐 **IP Tools Menu**\n\n"
            "**Available Commands:**\n"
            "• `/ip <address>` - IP lookup\n"
            "• `/whois <domain>` - Domain lookup\n"
            "• `/dorks <domain>` - Google dorks\n\n"
            "**Example:** `/ip 8.8.8.8`",
            parse_mode="Markdown"
        )
    
    elif data == "phone_tools":
        await query.edit_message_text(
            "📱 **Phone Tools Menu**\n\n"
            "**Available Commands:**\n"
            "• `/phone <number>` - Phone lookup\n\n"
            "**Example:** `/phone +919876543210`\n\n"
            "**Note:** Requires NUMVERIFY_API_KEY",
            parse_mode="Markdown"
        )
    
    elif data == "email_tools":
        await query.edit_message_text(
            "📧 **Email Tools Menu**\n\n"
            "**Available Commands:**\n"
            "• `/email <address>` - Breach check\n\n"
            "**Example:** `/email test@example.com`\n\n"
            "**Data Source:** Have I Been Pwned",
            parse_mode="Markdown"
        )
    
    elif data == "osint_tools":
        await query.edit_message_text(
            "🔍 **OSINT Tools Menu**\n\n"
            "**Available Commands:**\n"
            "• `/user <username>` - Username search\n"
            "• `/reverse <image_url>` - Reverse image\n"
            "• `/hash <type> <hash>` - Hash cracker\n\n"
            "**Example:** `/user john`",
            parse_mode="Markdown"
        )
    
    elif data == "utility_tools":
        await query.edit_message_text(
            "🛠️ **Utility Tools Menu**\n\n"
            "**Available Commands:**\n"
            "• `/base64 <encode/decode> <text>`\n"
            "• `/qr <text>` - QR generator\n"
            "• `/apis` - Check API status\n\n"
            "**Example:** `/qr https://google.com`",
            parse_mode="Markdown"
        )
    
    elif data == "help_menu":
        await self.help_command(update, context)

def _is_valid_ip(self, ip: str) -> bool:
    """Basic IP validation"""
    import re
    
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    # Basic IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    
    if re.match(ipv6_pattern, ip):
        return True
    
    return False

def setup_handlers(self):
    """Setup all command handlers"""
    # Command handlers
    self.application.add_handler(CommandHandler("start", self.start_command))
    self.application.add_handler(CommandHandler("help", self.help_command))
    self.application.add_handler(CommandHandler("ip", self.ip_command))
    self.application.add_handler(CommandHandler("phone", self.phone_command))
    self.application.add_handler(CommandHandler("email", self.email_command))
    self.application.add_handler(CommandHandler("whois", self.whois_command))
    self.application.add_handler(CommandHandler("reverse", self.reverse_command))
    self.application.add_handler(CommandHandler("hash", self.hash_command))
    self.application.add_handler(CommandHandler("user", self.user_command))
    self.application.add_handler(CommandHandler("dorks", self.dorks_command))
    self.application.add_handler(CommandHandler("base64", self.base64_command))
    self.application.add_handler(CommandHandler("qr", self.qr_command))
    self.application.add_handler(CommandHandler("apis", self.apis_command))
    
    # Button handler
    self.application.add_handler(CallbackQueryHandler(self.button_handler))

def run(self):
    """Run the bot"""
    # Create application
    self.application = Application.builder().token(self.token).build()
    
    # Setup handlers
    self.setup_handlers()
    
    print("=" * 50)
    print("🚀 Telegram OSINT Bot - Discord Style Structure")
    print("=" * 50)
    print("📁 Structure: app.py → cogs/ → utils/ → data/")
    print("🔧 APIs: ipinfo, numverify, whoisfreaks, serpapi, HIBP")
    print("🛠️ Tools: IP, Phone, Email, WHOIS, Hash, Username, QR")
    print("=" * 50)
    print("🤖 Starting bot...")
    
    # Start polling
    self.application.run_polling(allowed_updates=None)
