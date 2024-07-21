from typing import Optional

from .artifact import Artifact


class Context(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "func_addr",
        "screen_name"
    )

    def __init__(self, addr: int = None, func_addr: Optional[int] = None, screen_name: str = None, **kwargs):
        self.addr: Optional[int] = addr
        self.func_addr: Optional[int] = func_addr
        self.screen_name: str = screen_name
        super().__init__(**kwargs)

    def __str__(self):
        post_text = f" screen={self.screen_name}" if self.screen_name else ""
        if self.func_addr is not None:
            post_text = f"@{hex(self.func_addr)}" + post_text
            if self.addr is not None:
                post_text = hex(self.addr) + post_text

        return f"<Context {post_text}>"
