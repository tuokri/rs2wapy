from typing import Union


class EGSID:

    def __init__(self, ident: Union[int, str]):
        if isinstance(ident, str):
            ident = int(ident, 16)
        self._ident = ident

    @property
    def ident(self) -> int:
        return self._ident

    @ident.setter
    def ident(self, ident: int):
        self._ident = ident
