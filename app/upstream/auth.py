import base64

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.session import get_session

from app.config.models import AppConfig, AuthType


class UpstreamAuthError(Exception):
    pass


def _default_credentials() -> Credentials:
    credentials = get_session().get_credentials()
    if credentials is None:
        raise UpstreamAuthError("AWS credentials not found for aws_sigv4 upstream")
    return credentials


class Authenticator:
    def __init__(self, aws_credentials: Credentials | None = None) -> None:
        self._aws_credentials = aws_credentials

    def _credentials(self) -> Credentials:
        if self._aws_credentials is None:
            self._aws_credentials = _default_credentials()
        return self._aws_credentials

    def headers_for(self, app: AppConfig, method: str, url: str, content_type: str | None, body: bytes) -> dict[str, str]:
        auth = app.auth
        secret = auth.secret.get_secret_value() if auth.secret else None

        match auth.type:
            case AuthType.NONE:
                return {}
            case AuthType.BEARER:
                return {"Authorization": f"Bearer {secret}"}
            case AuthType.API_KEY_HEADER:
                return {auth.header: secret}
            case AuthType.BASIC:
                return {"Authorization": "Basic " + base64.b64encode(secret.encode()).decode()}
            case AuthType.AWS_SIGV4:
                return self._sigv4(app, method, url, content_type, body)

    def _sigv4(self, app: AppConfig, method: str, url: str, content_type: str | None, body: bytes) -> dict[str, str]:
        signed = {"Content-Type": content_type} if content_type else {}
        request = AWSRequest(method=method, url=url, data=body, headers=signed)
        frozen = self._credentials().get_frozen_credentials()
        SigV4Auth(frozen, app.auth.aws_service, app.auth.aws_region).add_auth(request)
        return {name: value for name, value in request.headers.items() if name.lower() != "content-type"}
