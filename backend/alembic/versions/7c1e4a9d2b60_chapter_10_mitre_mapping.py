"""chapter 10 mitre mapping entity

Adds ``mitre_mappings`` (Bible Ch10 step 4). One row is a mapped technique
for a user-day, or the explicit record that the user-day was evaluated and
nothing mapped. Check constraints: status value; a mapped row names its
technique, tactic, rule, triggering column and evidence grade; an unmapped
row names no technique; evidence grade; mitre_context in [0, 1]. Two
indexes (user-day, technique). Written by hand to match the ORM model and
checked with ``alembic upgrade head --sql``; the Alert foreign key is added
in Chapter 12.

Revision ID: 7c1e4a9d2b60
Revises: 50ba9f46d2ed
Create Date: 2026-09-29 12:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '7c1e4a9d2b60'
down_revision: Union[str, Sequence[str], None] = '50ba9f46d2ed'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('mitre_mappings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.String(length=64), nullable=False),
    sa.Column('activity_date', sa.Date(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('technique_id', sa.String(length=16), nullable=True),
    sa.Column('technique_name', sa.Text(), nullable=True),
    sa.Column('tactic', sa.String(length=64), nullable=True),
    sa.Column('rule_id', sa.String(length=64), nullable=True),
    sa.Column('evidence', sa.String(length=16), nullable=True),
    sa.Column('trigger_column', sa.String(length=128), nullable=True),
    sa.Column('trigger_value', sa.Float(), nullable=True),
    sa.Column('strength', sa.Float(), nullable=True),
    sa.Column('mitre_context', sa.Float(), nullable=True),
    sa.Column('unmapped_behaviours', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=True),
    sa.Column('ruleset_version', sa.String(length=32), nullable=False),
    sa.Column('ruleset_hash', sa.String(length=16), nullable=False),
    sa.Column('attack_version', sa.String(length=16), nullable=False),
    sa.Column('reference_id', sa.String(length=64), nullable=False),
    sa.Column('mitre_run_id', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("status IN ('mapped', 'unmapped')", name=op.f('ck_mitre_mappings_status_value')),
    sa.CheckConstraint("status <> 'mapped' OR (technique_id IS NOT NULL AND tactic IS NOT NULL AND rule_id IS NOT NULL AND trigger_column IS NOT NULL AND evidence IS NOT NULL)", name=op.f('ck_mitre_mappings_mapped_is_traceable')),
    sa.CheckConstraint("status <> 'unmapped' OR (technique_id IS NULL AND rule_id IS NULL)", name=op.f('ck_mitre_mappings_unmapped_has_no_technique')),
    sa.CheckConstraint("evidence IS NULL OR evidence IN ('observed', 'indicated')", name=op.f('ck_mitre_mappings_evidence_grade')),
    sa.CheckConstraint('mitre_context IS NULL OR (mitre_context >= 0 AND mitre_context <= 1)', name=op.f('ck_mitre_mappings_context_range')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_mitre_mappings'))
    )
    op.create_index('ix_mitre_mappings_user_day', 'mitre_mappings', ['user_id', 'activity_date'], unique=False)
    op.create_index('ix_mitre_mappings_technique_id', 'mitre_mappings', ['technique_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_mitre_mappings_technique_id', table_name='mitre_mappings')
    op.drop_index('ix_mitre_mappings_user_day', table_name='mitre_mappings')
    op.drop_table('mitre_mappings')
