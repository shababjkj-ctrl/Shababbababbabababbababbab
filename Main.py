import asyncio
import master

if __name__ == "__main__":
    try:
        asyncio.run(master.main())
    except KeyboardInterrupt:
        master.log_warn("Program stopped by user.")
