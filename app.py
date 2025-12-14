"""
Main application file - Discord bot structure style
"""
import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/logs/bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def check_environment():
    """Check if all required environment variables are set"""
    required_vars = ['TELEGRAM_BOT_TOKEN']
    optional_vars = ['IPINFO_TOKEN', 'NUMVERIFY_KEY', 'WHOISFREAKS_KEY', 'SERPAPI_KEY']
    
    missing = []
    for var in required_vars:
        if not os.getenv(var):
            missing.append(var)
    
    if missing:
        logger.error(f"Missing required environment variables: {missing}")
        return False
    
    logger.info("Environment check passed")
    return True

def main():
    """Main entry point"""
    from cogs.cyber_tools import CyberToolsBot
    
    # Check environment
    if not check_environment():
        print("❌ Missing environment variables!")
        print("Please set TELEGRAM_BOT_TOKEN and other API keys")
        return
    
    # Get token
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    
    # Create and run bot
    bot = CyberToolsBot(token)
    
    try:
        logger.info("Starting Telegram OSINT Bot...")
        bot.run()
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Bot crashed: {e}")

if __name__ == "__main__":
    # Create data directory if not exists
    os.makedirs('data/logs', exist_ok=True)
    
    main()
