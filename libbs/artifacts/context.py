from typing import Optional

from .artifact import Artifact


class Context(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "func_addr",
        "line_number",
        "screen_name",
        "variable"
    )

    def __init__(
        self,
        addr: Optional[int] = None,
        func_addr: Optional[int] = None,
        line_number: Optional[int] = None,
        screen_name: Optional[str] = None,
        variable: Optional[str] = None,
        **kwargs
    ):
        self.addr = addr
        self.func_addr = func_addr
        self.line_number = line_number
        self.screen_name = screen_name
        self.variable = variable
        super().__init__(**kwargs)

    def __str__(self):
        post_text = f" screen={self.screen_name}" if self.screen_name else ""
        post_text += f" var={self.variable}" if self.variable else ""
        if self.func_addr is not None:
            post_text = f"@{hex(self.func_addr)}" + post_text
            if self.addr is not None:
                post_text = hex(self.addr) + post_text
        if self.line_number is not None:
            post_text += f" line={self.line_number}"

        return f"<Context {post_text}>"
