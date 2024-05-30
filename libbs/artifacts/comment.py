from typing import Optional

from .artifact import Artifact


class Comment(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "func_addr",
        "comment",
        "decompiled",
    )

    def __init__(
        self,
        addr: int = None,
        comment: Optional[str] = None,
        func_addr: int = None,
        decompiled: bool = False,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.addr = addr
        self.comment = self.linewrap_comment(comment) if comment else None
        self.func_addr = func_addr
        self.decompiled = decompiled

    def __str__(self):
        return f"<Comment: @{hex(self.addr)} len={len(self.comment)}>"

    @staticmethod
    def linewrap_comment(comment: str, width=80):
        lines = comment.splitlines()
        final_comment = ""

        for line in lines:
            if len(line) < width:
                final_comment += line + "\n"
                continue

            for i, c in enumerate(line):
                if i % width == 0 and i != 0:
                    final_comment += "\n"
                final_comment += c

            final_comment += "\n"

        return final_comment

    def nonconflict_merge(self, obj2: "Comment", **kwargs) -> "Comment":
        obj1: "Comment" = self.copy()
        if not obj2 or obj1 == obj2:
            return obj1

        merge_comment = obj1
        return merge_comment
