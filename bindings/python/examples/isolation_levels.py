from lib.iota_sdk import *
import asyncio
async def main():
    print("=== Isolation Levels ===\n1.Read-uncommitted 2.Read-committed 3.Repeatable-read\n")
if __name__ == "__main__":
    asyncio.run(main())
