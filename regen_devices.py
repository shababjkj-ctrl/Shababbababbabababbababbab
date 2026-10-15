# Give every saved account a brand-new device. Stop the bot first, run this once, then start the bot.
from device_pool import regenerate_all, CATALOG

if __name__ == "__main__":
    n = regenerate_all("devices.json")
    print(f"Done: {n} accounts got new devices ({len(CATALOG)} phone models in pool). Old file saved as devices.json.bak")
