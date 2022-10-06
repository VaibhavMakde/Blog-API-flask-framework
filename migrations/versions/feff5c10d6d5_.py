"""empty message

Revision ID: feff5c10d6d5
Revises: 
Create Date: 2022-10-06 12:19:47.274585

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'feff5c10d6d5'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint(None, 'user', ['email'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'user', type_='unique')
    # ### end Alembic commands ###
