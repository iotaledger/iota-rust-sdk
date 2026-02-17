from lib.iota_sdk import *
import asyncio
async def main():
    print("=== Happens-Before ===\n1.Synchronizes-with 2.Program-order 3.DRFO\n")
if __name__ == "__main__":
    asyncio.run(main())
