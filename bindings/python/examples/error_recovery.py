from lib.iota_sdk import *
import asyncio
async def main():
    print("=== Error Recovery ===\n")
    print("1.Retry 2.Timeout 3.Fallback 4.Robust\n")
    print("Completed!")
if __name__ == "__main__":
    asyncio.run(main())
