"""একক ত্রুটি টাইপ। সব API ত্রুটি একই JSON ফরম্যাটে যায় (§৫)।"""

from typing import Any


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        retry_after: int | None = None,
        details: list[dict] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after
        self.details = details

    def headers(self) -> dict[str, str]:
        return {"Retry-After": str(self.retry_after)} if self.retry_after is not None else {}

    def payload(self) -> dict[str, Any]:
        err: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.retry_after is not None:
            err["retry_after"] = self.retry_after
        if self.details:
            err["details"] = self.details
        return {"error": err}
