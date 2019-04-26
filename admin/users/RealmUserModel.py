class RealmUserModel:
    """User representation
    """
    def __init__(self, rep):
        self._rep = rep

    def __str__(self):
        return str(self._rep)

    def __getitem__(self, item):
        """
        Returns a value associated with the key
        :param item: a key
        :return: a value associated with the key
        """
        return self._rep[item]