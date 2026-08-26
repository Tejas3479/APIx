"""Add is_demo_data to notifiedrate.

Revision ID: 9f2c1a4b7e01
Revises: 15109c95aff3
Create Date: 2026-08-17
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9f2c1a4b7e01"
down_revision: str | None = "15109c95aff3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add is_demo_data flag to notifiedrate (seeded rates are demo)."""
    # Server default True so pre-existing seeded rows are correctly flagged.
    op.add_column(
        "notifiedrate",
        sa.Column(
            "is_demo_data", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )


def downgrade() -> None:
    """Remove the is_demo_data column."""
    op.drop_column("notifiedrate", "is_demo_data")
