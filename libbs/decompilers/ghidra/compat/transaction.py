from .state import get_current_program

class Transaction:
    def __init__(self, msg="BinSync transaction"):
        self._trans_msg = msg
        self.trans_id = None

    def __enter__(self):
        self.trans_id = get_current_program().startTransaction(self._trans_msg)

    def __exit__(self, exc_type, exc_val, exc_tb):
        get_current_program().endTransaction(self.trans_id, True)
