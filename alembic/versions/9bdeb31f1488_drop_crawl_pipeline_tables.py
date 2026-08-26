"""Drop Crawlix crawl-pipeline tables.

Revision ID: 9bdeb31f1488
Revises: 9f2c1a4b7e01
Create Date: 2026-08-17
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9bdeb31f1488"
down_revision: str | None = "9f2c1a4b7e01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Drop the multi-page crawl / batch / scheduled / destination tables."""
    op.drop_table("batchjob")
    op.drop_table("scheduledcrawl")
    op.drop_table("destination")
    op.drop_table("crawljob")


def downgrade() -> None:
    """Recreate the crawl pipeline tables (columns kept minimal)."""
    op.create_table(
        "crawljob",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("results", sa.JSON(), nullable=True),
        sa.Column("stats", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.String(), nullable=True),
        sa.Column("max_pages", sa.Integer(), nullable=False),
        sa.Column("max_depth", sa.Integer(), nullable=False),
        sa.Column("render_js", sa.Boolean(), nullable=False),
        sa.Column("output_format", sa.String(), nullable=False),
        sa.Column("webhook_url", sa.String(), nullable=True),
        sa.Column("destinations", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "destination",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "scheduledcrawl",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("cron_expression", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "batchjob",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_urls", sa.Integer(), nullable=False),
        sa.Column("processed_urls", sa.Integer(), nullable=False),
        sa.Column("webhook_url", sa.String(), nullable=True),
        sa.Column("export_path", sa.String(), nullable=True),
        sa.Column("error_message", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
