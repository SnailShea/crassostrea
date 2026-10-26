"""Error raised by the service layer (business rules shared by UI and API)."""


class ServiceError(ValueError):
    """A request that breaks a business rule.

    ``field`` names the offending input, ``status`` is the HTTP status the
    REST API answers with (422 invalid, 404 not found, 409 conflict).
    """

    def __init__(self, message, field=None, status=422):
        super().__init__(message)
        self.field = field
        self.status = status
