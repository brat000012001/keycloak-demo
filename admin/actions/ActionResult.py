class ActionResult:
    """
    The operations that affect a sub-set of users use the ActionResult
    to return the results of the operation
    """

    def __init__(self):
        self._processed = 0
        self._total = 0
        self._failed = 0
        self._skipped = 0

    def on_processed(self):
        self._processed += 1
        self._total += 1

    def on_skipped(self):
        self._skipped += 1
        self._total += 1

    def on_failed(self):
        self._failed += 1
        self._total += 1

    def processed(self): return self._processed

    def failed(self): return self._failed

    def total(self): return self._total

    def skipped(self): return self._skipped

