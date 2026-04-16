class AegirSecurityError(Exception):
    def __init__(self, message: str, status: int, code: str, correlationId: str | None, body):
        super().__init__(message)
        self.status = status
        self.code = code
        self.correlationId = correlationId
        self.body = body
