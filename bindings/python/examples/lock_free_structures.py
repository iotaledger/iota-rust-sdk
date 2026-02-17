from lib.iota_sdk import *
import asyncio
async def main():
    print("=== Lock-Free ===\n1.CAS 2.ABA 3.Memory-ordering\n")
if __name__ == "__main__":
    asyncio.run(main())
