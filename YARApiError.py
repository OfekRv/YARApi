#TODO: add status code
class YARApiError(Exception):
    pass

class YARApiFileNotFoundError(YARApiError):
    pass

class YARApiRulesFileTypeError(YARApiError):
    pass

class YARApiRulesFileSyntaxError(YARApiError):
    pass








