# Copyright (c) 2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Simple async queue/deque implementation."""

import asyncio
from collections import deque
from typing import Callable, Deque, Generic, TypeVar

T = TypeVar("T")


class AsyncDeque(Generic[T]):
    """A coroutine-safe, double-ended queue (Deque) for asyncio."""

    def __init__(self, maxsize: int = 0):
        self._maxsize: int = maxsize
        self._queue: Deque[T] = deque()
        self._getters: Deque[asyncio.Future] = deque()
        self._putters: Deque[asyncio.Future] = deque()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} qsize={self.qsize()} maxsize={self.maxsize}>"

    @property
    def maxsize(self) -> int:
        return self._maxsize

    def qsize(self) -> int:
        return len(self._queue)

    def empty(self) -> bool:
        return not self._queue

    def full(self) -> bool:
        if self._maxsize <= 0:
            return False
        return len(self._queue) >= self._maxsize

    def _wakeup_next(self, waiters: Deque[asyncio.Future]) -> None:
        """Wake up the first non-canceled future in the waiters queue."""
        while waiters:
            waiter = waiters.popleft()
            if not waiter.done():
                waiter.set_result(None)
                break

    async def _wait_for(
        self, condition: Callable[[], bool], waiters: Deque[asyncio.Future]
    ) -> None:
        """Helper to manage the boilerplate of awaiting queue capacity or items."""
        while condition():
            waiter = asyncio.get_running_loop().create_future()
            waiters.append(waiter)
            try:
                await waiter
            except BaseException:
                waiter.cancel()
                try:
                    waiters.remove(waiter)
                except ValueError:
                    pass
                # Pass the baton if we were awoken but aborted before consuming
                if not condition() and not waiter.cancelled():
                    self._wakeup_next(waiters)
                raise

    # --- Non-Blocking API (Synchronous) ---

    def append_nowait(self, item: T) -> None:
        if self.full():
            raise asyncio.QueueFull
        self._queue.append(item)
        self._wakeup_next(self._getters)

    def appendleft_nowait(self, item: T) -> None:
        if self.full():
            raise asyncio.QueueFull
        self._queue.appendleft(item)
        self._wakeup_next(self._getters)

    def pop_nowait(self) -> T:
        if self.empty():
            raise asyncio.QueueEmpty
        item = self._queue.pop()
        self._wakeup_next(self._putters)
        return item

    def popleft_nowait(self) -> T:
        if self.empty():
            raise asyncio.QueueEmpty
        item = self._queue.popleft()
        self._wakeup_next(self._putters)
        return item

    # --- Blocking API (Asynchronous) ---

    async def append(self, item: T) -> None:
        """Append an item to the right. Block if the queue is full."""
        await self._wait_for(self.full, self._putters)
        self.append_nowait(item)

    async def appendleft(self, item: T) -> None:
        """Append an item to the left. Block if the queue is full."""
        await self._wait_for(self.full, self._putters)
        self.appendleft_nowait(item)

    async def pop(self) -> T:
        """Remove and return an item from the right. Block if empty."""
        await self._wait_for(self.empty, self._getters)
        return self.pop_nowait()

    async def popleft(self) -> T:
        """Remove and return an item from the left. Block if empty."""
        await self._wait_for(self.empty, self._getters)
        return self.popleft_nowait()
