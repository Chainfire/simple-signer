from io import SEEK_SET
from typing import Generator, Optional, List


class BlockGenerator:
    def __init__(self):
        pass

    def generator(self) -> Generator[bytes, None, None]:
        raise NotImplementedError()


class FileBlockGenerator:
    def __init__(self, filename: str, start: Optional[int]=None, count: Optional[int]=None):
        self._filename = filename
        self._start = start
        self._count = count

    def generator(self) -> Generator[bytes, None, None]:
        with open(self._filename, 'rb') as f:
            if self._start:
                f.seek(self._start, SEEK_SET)
            count = 0
            while not self._count or count < self._count:
                block = f.read(64 * 1024)
                if not block:
                    break
                if self._count and count + len(block) > self._count:
                    block = block[:self._count - count]
                yield block
                count += len(block)


class BytesBlockGenerator:
    def __init__(self, memory: bytes):
        self._memory = memory

    def generator(self) -> Generator[bytes, None, None]:
        yield self._memory


class ChainedBlockGenerator:
    def __init__(self, generators: List[Generator[bytes, None, None]]):
        self._generators = generators

    def generator(self) -> Generator[bytes, None, None]:
        for generator in self._generators:
            for block in generator:
                yield block
