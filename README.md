# FastAPI Unit Testing Workshop

A demo FastAPI application designed for learning pytest unit testing patterns.

## Quick Start

```bash
# install dependencies (Poetry v2)
poetry install --no-root
eval "$(poetry env activate)"

# seed the database with sample data
python -m project.db.seed

# run the app
uvicorn project.main:app --reload

# run tests
pytest tests/unit/ -v

# run with coverage
pytest tests/unit/ --cov=project --cov-report=term-missing
```

## Demo Credentials

After seeding, the following users are available:

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| john | john123 | User |
| jane | jane123 | User |
| bob | bob123 | User |

## Project Structure

```
project/
├── main.py              # FastAPI app factory
├── config.py            # Settings with pydantic-settings
├── security.py          # JWT + password utilities
├── exceptions.py        # Domain exceptions
├── dependencies.py      # Auth + pagination deps
├── db/
│   ├── db.py            # Engine + session
│   └── models/          # SQLAlchemy models
├── routers/             # API endpoints
├── services/            # Business logic
└── utils/
    └── pagination.py    # Pagination utilities

tests/
├── conftest.py          # Fixtures
└── unit/
    ├── test_level_1_basics.py      # Simple assertions
    ├── test_level_2_exceptions.py  # Exception testing
    └── test_level_3_mocking.py     # Mocking/patching

docs/
├── WORKSHOP.md          # Main workshop guide
├── LEVEL_1.md           # Simple tests guide
├── LEVEL_2.md           # Exception testing guide
└── LEVEL_3.md           # Mocking guide
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Get access token |
| GET | `/tasks` | List tasks (paginated) |
| POST | `/tasks` | Create task |
| GET | `/tasks/{uuid}` | Get task |
| PATCH | `/tasks/{uuid}` | Update task |
| DELETE | `/tasks/{uuid}` | Delete task (admin) |

## Workshop

See [docs/WORKSHOP.md](docs/WORKSHOP.md) for the complete unit testing workshop guide.

### Running Test Levels

```bash
# run all unit tests
pytest tests/unit/ -v

# run by level marker
pytest -k level_1 -v    # simple assertions
pytest -k level_2 -v    # exception testing
pytest -k level_3 -v    # mocking/patching

# run with coverage report
pytest tests/unit/ --cov=project --cov-report=html
open htmlcov/index.html
```

## Technology Stack

- **Python 3.12+**
- **FastAPI 0.118+** - Web framework
- **SQLAlchemy 2.0+** - ORM
- **Pydantic 2.0+** - Data validation
- **pytest 8.0+** - Testing framework
- **Poetry 2.0+** - Dependency management
