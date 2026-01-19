"""Test configuration and fixtures for pytest unit testing workshop."""

from datetime import datetime
from unittest.mock import Mock
from uuid import uuid4

import pytest

from project.config import Settings
from project.db.models.task import Task, TaskStatus
from project.db.models.user import Role, User


@pytest.fixture
def test_settings() -> Settings:
    """Provide test settings without loading from .env."""
    return Settings(
        DEBUG=True,
        SECRET_KEY="test-secret-key-for-testing",
        DB_TYPE="sqlite",
        DB_URL="sqlite:///:memory:",
        SQLALCHEMY_ECHO=False,
        ACCESS_TOKEN_EXPIRE_MINUTES=30,
    )


@pytest.fixture
def sample_user() -> Mock:
    """Create a sample user mock for testing (not persisted to DB)."""
    user = Mock(spec=User)
    user.uuid = uuid4()
    user.username = "testuser"
    user.email = "test@example.com"
    user.password_hash = "$2b$12$test_hash_placeholder"
    user.role = Role.USER.value
    user.created_at = datetime.now()
    return user


@pytest.fixture
def admin_user() -> Mock:
    """Create an admin user mock for testing (not persisted to DB)."""
    user = Mock(spec=User)
    user.uuid = uuid4()
    user.username = "admin"
    user.email = "admin@example.com"
    user.password_hash = "$2b$12$admin_hash_placeholder"
    user.role = Role.ADMIN.value
    user.created_at = datetime.now()
    return user


@pytest.fixture
def sample_task(sample_user: Mock) -> Mock:
    """Create a sample task mock for testing (not persisted to DB)."""
    task = Mock(spec=Task)
    task.uuid = uuid4()
    task.title = "Test Task"
    task.description = "A test task description"
    task.status = TaskStatus.TODO.value
    task.priority = 3
    task.due_date = None
    task.created_by = sample_user.uuid
    task.assigned_to = None
    task.created_at = datetime.now()
    return task
