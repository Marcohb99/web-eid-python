import aenum


class Command(aenum.StrEnum):
    GET_CERTIFICATE = "get-certificate",
    AUTHENTICATE = "authenticate",
    SIGN = "sign"
