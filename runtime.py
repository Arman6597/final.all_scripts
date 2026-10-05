"""Ограниченная очередь задач с обязательным завершением всех workers."""
import asyncio


async def bounded(items, operation, count):
    iterator = iter(items)

    async def worker():
        for item in iterator:
            await operation(item)

    tasks = [asyncio.create_task(worker()) for _ in range(count)]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
