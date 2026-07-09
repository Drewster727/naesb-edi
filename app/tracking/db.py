from pathlib import Path

from psycopg_pool import AsyncConnectionPool

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "db" / "migrations"


async def create_pool(database_url: str) -> AsyncConnectionPool:
    pool = AsyncConnectionPool(conninfo=database_url, open=False)
    await pool.open()
    return pool


async def run_migrations(pool: AsyncConnectionPool) -> None:
    """Apply any db/migrations/*.sql file not yet recorded in schema_migrations,
    in filename order. Each file runs in its own transaction alongside the
    bookkeeping insert, so a failed migration doesn't get marked as applied."""
    async with pool.connection() as conn:
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        async with conn.cursor() as cur:
            await cur.execute("SELECT filename FROM schema_migrations")
            applied = {row[0] for row in await cur.fetchall()}

        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if path.name in applied:
                continue
            sql = path.read_text()
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations (filename) VALUES (%s)", (path.name,)
                )
