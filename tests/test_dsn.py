import pytest

from app.db.dsn import DatabaseUrlError, parse_database_url

POOLER = "aws-0-eu-north-1.pooler.supabase.com"


def test_standard_encoded_url() -> None:
    params = parse_database_url(f"postgresql://postgres.abcd:p%40ss%23word@{POOLER}:5432/postgres")

    assert params.host == POOLER
    assert params.port == 5432
    assert params.user == "postgres.abcd"
    assert params.password == "p@ss#word"
    assert params.database == "postgres"


@pytest.mark.parametrize(
    "password",
    ["p@ss#word", "a/b?c:d@e", "100%sure", "ends-with@", "#start", "sp ace&amp=1"],
)
def test_raw_password_with_special_characters(password: str) -> None:
    params = parse_database_url(f"postgresql://postgres.abcd:{password}@{POOLER}:5432/postgres")

    assert params.password == password
    assert params.host == POOLER
    assert params.user == "postgres.abcd"
    assert params.database == "postgres"


def test_password_override_is_used_verbatim() -> None:
    params = parse_database_url(f"postgresql://postgres.abcd:ignored@{POOLER}:5432/postgres", "x%41y")

    assert params.password == "x%41y"


def test_url_without_password() -> None:
    params = parse_database_url(f"postgresql://postgres.abcd@{POOLER}/postgres", "secret")

    assert params.password == "secret"
    assert params.port == 5432


def test_defaults() -> None:
    params = parse_database_url("postgres://localhost")

    assert (params.host, params.port, params.user, params.database, params.password) == (
        "localhost",
        5432,
        "postgres",
        "postgres",
        None,
    )


def test_ipv6_host() -> None:
    params = parse_database_url("postgresql://u:p@[2a05:d016::1]:6543/db")

    assert params.host == "2a05:d016::1"
    assert params.port == 6543


def test_sslmode() -> None:
    params = parse_database_url(f"postgresql://u:p@{POOLER}:5432/postgres?sslmode=require")

    assert params.ssl == "require"
    assert params.as_kwargs()["ssl"] == "require"


@pytest.mark.parametrize(
    "url",
    [
        "mysql://u:p@h/db",
        "postgresql://u:p@:5432/db",
        "postgresql://u:p@h:abc/db",
        "postgresql://u:p@h/db?application_name=x",
        "postgresql://u:p@h/db?sslmode=bogus",
    ],
)
def test_invalid_urls(url: str) -> None:
    with pytest.raises(DatabaseUrlError):
        parse_database_url(url)


def test_describe_hides_password() -> None:
    params = parse_database_url(f"postgresql://postgres.abcd:topsecret@{POOLER}:5432/postgres")

    assert "topsecret" not in str(params.describe())
