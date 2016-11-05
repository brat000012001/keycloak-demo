class ApiResponse:
    def __init__(self, status, reason, data):
        self._status = status
        self._reason = reason
        self._data = data
        if not self._data is None:
            self._data = self._data.decode('utf-8')

    def status(self): return self._status
    def reason(self): return self._reason
    def data(self): return self._data

    def __str__(self):
        return '{0}, {1},{2}'.format(self._status,self._reason,self._data)