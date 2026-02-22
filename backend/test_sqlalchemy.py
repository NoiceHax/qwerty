import asyncio
from sqlalchemy import select
from app.database import async_session_factory
from app.models.scan import Scan
import logging

logging.basicConfig(level=logging.INFO)

async def test():
    print("Testing SQLAlchemy query on 'scans' table...")
    async with async_session_factory() as session:
        try:
            # Try to fetch one scan
            result = await session.execute(select(Scan).limit(1))
            scan = result.scalar_one_or_none()
            if scan:
                print(f"Success! Found scan with id: {scan.id}")
                print(f"ai_summary: {scan.ai_summary}")
                print(f"repo_intel: {scan.repo_intel}")
            else:
                print("Success! No scans found, but query worked.")
        except Exception as e:
            print(f"SQLAlchemy query failed: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
