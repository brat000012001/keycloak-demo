class HTTPHeader:
    '''Represents an HTTP header
    '''
    def __init__(self, name, value):
        self._name = name
        self._value = value

    def value(self): return self._value

    def name(self): return self._name

    def __str__(self):
        return '{0}: {1}'.format(self._name, self._value)

    def __repr__(self):
        return self.__str__()