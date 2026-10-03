import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote

SCHEMES = {"postgres", "postgresql"}
SSL_MODES = {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class DatabaseUrlError(ValueError):
    pass


@dataclass(frozen=True)
class ConnectParams:
    host: str
    port: int
    user: str
    password: str | None
    database: str
    ssl: str | None

    def as_kwargs(self) -> dict:
        kwargs = {
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "password": self.password,
            "database": self.database,
        }
        if self.ssl is not None:
            kwargs["ssl"] = self.ssl
        return kwargs

    def describe(self) -> dict:
        return {"host": self.host, "port": self.port, "user": self.user, "database": self.database, "ssl": self.ssl}


def _decode_password(raw: str) -> str:
    if INVALID_PERCENT_ESCAPE.search(raw):
        return raw
    return unquote(raw)


def _split_host_port(hostport: str) -> tuple[str, int]:
    if hostport.startswith("["):
        host, _, after = hostport[1:].partition("]")
        port = after.removeprefix(":")
    elif ":" in hostport:
        host, _, port = hostport.rpartition(":")
    else:
        host, port = hostport, ""
    if not host:
        raise DatabaseUrlError("database url has no host")
    if port and not port.isdigit():
        raise DatabaseUrlError("database url has an invalid port")
    return host, int(port) if port else 5432


def parse_database_url(url: str, password_override: str | None = None) -> ConnectParams:
    scheme, separator, rest = url.strip().partition("://")
    if not separator or scheme not in SCHEMES:
        raise DatabaseUrlError("database url must start with postgresql://")

    credentials, at, location = rest.rpartition("@")
    if not at:
        credentials, location = "", rest

    user, _, raw_password = credentials.partition(":")
    hostport, _, tail = location.partition("/")
    database, _, query = tail.partition("?")
    host, port = _split_host_port(hostport)

    ssl = None
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key != "sslmode":
            raise DatabaseUrlError(f"unsupported database url parameter: {key}")
        if value not in SSL_MODES:
            raise DatabaseUrlError(f"unsupported sslmode: {value}")
        ssl = value

    if password_override:
        password = password_override
    elif raw_password:
        password = _decode_password(raw_password)
    else:
        password = None

    return ConnectParams(
        host=host,
        port=port,
        user=unquote(user) or "postgres",
        password=password,
        database=unquote(database) or "postgres",
        ssl=ssl,
    )
