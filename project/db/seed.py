"""Database seeder for development and testing."""

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from project.db.models.task import Task, TaskStatus
from project.db.models.user import Role, User
from project.security import encrypt_password


def seed_users(session: Session) -> dict[str, User]:
    """Create sample users."""
    users = {}

    # admin user
    admin = User(
        username="admin",
        email="admin@example.com",
        password_hash=encrypt_password("admin123"),
        role=Role.ADMIN.value,
    )
    session.add(admin)
    users["admin"] = admin

    # regular users
    for i, (name, email) in enumerate([
        ("john", "john@example.com"),
        ("jane", "jane@example.com"),
        ("bob", "bob@example.com"),
    ], start=1):
        user = User(
            username=name,
            email=email,
            password_hash=encrypt_password(f"{name}123"),
            role=Role.USER.value,
        )
        session.add(user)
        users[name] = user

    session.flush()  # get uuids
    return users


def seed_tasks(session: Session, users: dict[str, User]) -> list[Task]:
    """Create sample tasks."""
    tasks_data = [
        {
            "title": "Setup development environment",
            "description": "Install Python, Poetry, and configure IDE",
            "status": TaskStatus.DONE.value,
            "priority": 5,
            "created_by": users["admin"].uuid,
            "assigned_to": users["john"].uuid,
        },
        {
            "title": "Write API documentation",
            "description": "Document all endpoints in OpenAPI format",
            "status": TaskStatus.IN_PROGRESS.value,
            "priority": 4,
            "created_by": users["admin"].uuid,
            "assigned_to": users["jane"].uuid,
        },
        {
            "title": "Implement user authentication",
            "description": "Add JWT-based authentication with bcrypt password hashing",
            "status": TaskStatus.DONE.value,
            "priority": 5,
            "created_by": users["john"].uuid,
            "assigned_to": users["john"].uuid,
        },
        {
            "title": "Create database models",
            "description": "Define SQLAlchemy models for User and Task",
            "status": TaskStatus.DONE.value,
            "priority": 4,
            "created_by": users["john"].uuid,
            "assigned_to": None,
        },
        {
            "title": "Add pagination support",
            "description": "Implement limit/offset pagination for list endpoints",
            "status": TaskStatus.IN_PROGRESS.value,
            "priority": 3,
            "created_by": users["jane"].uuid,
            "assigned_to": users["bob"].uuid,
        },
        {
            "title": "Write unit tests",
            "description": "Create pytest unit tests for services and utilities",
            "status": TaskStatus.TODO.value,
            "priority": 4,
            "created_by": users["admin"].uuid,
            "assigned_to": users["jane"].uuid,
            "due_date": datetime.now() + timedelta(days=7),
        },
        {
            "title": "Code review PR #42",
            "description": "Review the authentication implementation",
            "status": TaskStatus.TODO.value,
            "priority": 3,
            "created_by": users["bob"].uuid,
            "assigned_to": users["admin"].uuid,
        },
        {
            "title": "Fix bug in task filtering",
            "description": "Status filter returns wrong results when combined with pagination",
            "status": TaskStatus.TODO.value,
            "priority": 2,
            "created_by": users["jane"].uuid,
            "assigned_to": None,
        },
        {
            "title": "Update dependencies",
            "description": "Upgrade FastAPI and SQLAlchemy to latest versions",
            "status": TaskStatus.TODO.value,
            "priority": 1,
            "created_by": users["admin"].uuid,
            "assigned_to": users["bob"].uuid,
            "due_date": datetime.now() + timedelta(days=14),
        },
        {
            "title": "Deploy to staging",
            "description": "Deploy the application to staging environment for testing",
            "status": TaskStatus.TODO.value,
            "priority": 3,
            "created_by": users["admin"].uuid,
            "assigned_to": None,
            "due_date": datetime.now() + timedelta(days=3),
        },
    ]

    tasks = []
    for data in tasks_data:
        task = Task(**data)
        session.add(task)
        tasks.append(task)

    return tasks


def seed_database(session: Session) -> None:
    """Seed the database with sample data."""
    print("Seeding database...")

    users = seed_users(session)
    print(f"  Created {len(users)} users")

    tasks = seed_tasks(session, users)
    print(f"  Created {len(tasks)} tasks")

    session.commit()
    print("Database seeded successfully!")


def clear_database(session: Session) -> None:
    """Clear all data from the database."""
    session.query(Task).delete()
    session.query(User).delete()
    session.commit()
    print("Database cleared.")


if __name__ == "__main__":
    from project.db.db import SessionLocal
    from project.db.models.base import Base
    from project.db.db import engine

    # create tables
    Base.metadata.create_all(bind=engine)

    # seed data
    with SessionLocal() as session:
        seed_database(session)
