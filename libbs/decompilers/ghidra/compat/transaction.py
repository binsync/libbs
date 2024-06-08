from .state import get_current_program


class Transaction:
    def __init__(self, flat_api, msg="BinSync transaction"):
        self._trans_msg = msg
        self._flat_api = flat_api
        self.trans_id = None

    def __enter__(self):
        self.trans_id = get_current_program(flat_api=self._flat_api).startTransaction(self._trans_msg)

    def __exit__(self, exc_type, exc_val, exc_tb):
        get_current_program(flat_api=self._flat_api).endTransaction(self.trans_id, True)
