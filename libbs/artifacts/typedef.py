from typing import Optional

from .artifact import Artifact


class Typedef(Artifact):
    """
    Describe a typedef. As an example:
    typedef struct MyStruct {
        int a;
        int b;
    } my_struct_t;

    name="my_struct_t"
    type="MyStruct"

    Another example:
    typedef int my_int_t;

    name="my_int_t"
    type="int"
    """

    __slots__ = Artifact.__slots__ + (
        "name",
        "type",
    )

    def __init__(
        self,
        name: str = None,
        type_: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.name: str = name
        self.type: str = type_

    def __str__(self):
        return f"<TypeDef: {self.name}={self.type}>"
