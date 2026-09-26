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

import asyncio
import threading

import pytest

from rs2wapy.deque import AsyncDeque


def test_nowait_deque_order_and_bounds() -> None:
    queue = AsyncDeque[str](maxsize=2)

    queue.append_nowait("right")
    queue.appendleft_nowait("left")

    with pytest.raises(asyncio.QueueFull):
        queue.append_nowait("full")

    assert queue.pop_nowait() == "right"
    assert queue.popleft_nowait() == "left"

    with pytest.raises(asyncio.QueueEmpty):
        queue.pop_nowait()


def test_nowait_seeding_before_loop_binding() -> None:
    queue = AsyncDeque[str]()

    queue.append_nowait("seed")

    assert queue.popleft_nowait() == "seed"


def test_bounded_producers_and_consumers_resume() -> None:
    async def scenario() -> None:
        producer_queue = AsyncDeque[str](maxsize=1)
        await producer_queue.append("first")
        producer = asyncio.create_task(producer_queue.append("second"))
        await asyncio.sleep(0)

        assert not producer.done()
        assert await producer_queue.popleft() == "first"
        await asyncio.wait_for(producer, timeout=1)
        assert await producer_queue.popleft() == "second"

        consumer_queue = AsyncDeque[str]()
        consumer = asyncio.create_task(consumer_queue.popleft())
        await asyncio.sleep(0)

        assert not consumer.done()
        await consumer_queue.append("item")
        assert await asyncio.wait_for(consumer, timeout=1) == "item"

        end_queue = AsyncDeque[str]()
        await end_queue.appendleft("left")
        await end_queue.append("right")
        assert await end_queue.pop() == "right"
        assert await end_queue.popleft() == "left"

    asyncio.run(scenario())


def test_cancelled_waiter_does_not_block_later_work() -> None:
    async def scenario() -> None:
        queue = AsyncDeque[str](maxsize=1)
        await queue.append("seed")
        cancelled_producer = asyncio.create_task(queue.append("cancelled"))
        await asyncio.sleep(0)

        cancelled_producer.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled_producer

        assert await queue.popleft() == "seed"
        await queue.append("replacement")
        assert await queue.popleft() == "replacement"

    asyncio.run(scenario())


def test_wake_then_cancel_passes_baton_to_next_producer() -> None:
    async def scenario() -> None:
        queue = AsyncDeque[str](maxsize=1)
        await queue.append("seed")
        first = asyncio.create_task(queue.append("first"))
        second = asyncio.create_task(queue.append("second"))
        await asyncio.sleep(0)

        assert await queue.popleft() == "seed"
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first

        await asyncio.wait_for(second, timeout=1)
        assert await queue.popleft() == "second"

    asyncio.run(scenario())


def test_wake_then_cancel_passes_baton_to_next_consumer() -> None:
    async def scenario() -> None:
        queue = AsyncDeque[str]()
        first = asyncio.create_task(queue.popleft())
        second = asyncio.create_task(queue.popleft())
        await asyncio.sleep(0)

        await queue.append("item")
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first

        assert await asyncio.wait_for(second, timeout=1) == "item"

    asyncio.run(scenario())


def test_bound_deque_rejects_other_loops_threads_and_sync_mutation() -> None:
    queue = AsyncDeque[str]()

    async def bind() -> None:
        await queue.append("item")

    asyncio.run(bind())

    assert queue.qsize() == 1
    assert not queue.empty()

    with pytest.raises(RuntimeError, match="bound event loop"):
        queue.append_nowait("outside-loop")

    async def other_loop() -> None:
        with pytest.raises(RuntimeError, match="bound event loop"):
            await queue.append("other-loop")

    asyncio.run(other_loop())

    thread_errors: list[BaseException] = []

    def mutate_from_thread() -> None:
        try:
            asyncio.run(queue.append("other-thread"))
        except BaseException as exc:
            thread_errors.append(exc)

    thread = threading.Thread(target=mutate_from_thread)
    thread.start()
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert len(thread_errors) == 1
    assert isinstance(thread_errors[0], RuntimeError)
