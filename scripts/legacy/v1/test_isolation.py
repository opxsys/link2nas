import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "backend"))

from storage.db import Database
from repositories.user_repository import UserRepository
from repositories.job_repository import JobRepository
from repositories.provider_config_repository import ProviderConfigRepository
from repositories.destination_config_repository import DestinationConfigRepository
from models.user import User
from models.job import Job
from models.provider_config import ProviderConfig
from models.destination_config import DestinationConfig


DB_PATH = ROOT_DIR / "data" / "link2nas_v2.sqlite3"


def now():
    return datetime.now(UTC).isoformat()


def main():
    db = Database(str(DB_PATH))
    run_id = uuid.uuid4().hex[:8]

    user_repo = UserRepository(db)
    job_repo = JobRepository(db)
    provider_repo = ProviderConfigRepository(db)
    dest_repo = DestinationConfigRepository(db)

    # --- users
    user_a = User(
        id=str(uuid.uuid4()),
        email=f"a_{run_id}@test.com",
        display_name="User A",
        role="user",
        is_active=True,
        created_at=now(),
        updated_at=now(),
    )

    user_b = User(
        id=str(uuid.uuid4()),
        email=f"b_{run_id}@test.com",
        display_name="User B",
        role="user",
        is_active=True,
        created_at=now(),
        updated_at=now(),
    )

    user_repo.create(user_a)
    user_repo.create(user_b)

    # --- jobs A
    for i in range(2):
        job_repo.create(
            Job(
                id=str(uuid.uuid4()),
                user_id=user_a.id,
                source_type="magnet",
                source_value=f"magnet_A_{i}",
                status="created",
                provider_name=None,
                destination_name=None,
                created_at=now(),
                updated_at=now(),
            )
        )

    # --- jobs B
    job_b = Job(
        id=str(uuid.uuid4()),
        user_id=user_b.id,
        source_type="magnet",
        source_value="magnet_B",
        status="created",
        provider_name=None,
        destination_name=None,
        created_at=now(),
        updated_at=now(),
    )
    job_repo.create(job_b)

    # --- TEST 1 : list isolation
    jobs_a = job_repo.list_for_user(user_a.id)
    jobs_b = job_repo.list_for_user(user_b.id)

    print(f"User A jobs: {len(jobs_a)} (expected 2)")
    print(f"User B jobs: {len(jobs_b)} (expected 1)")

    # --- TEST 2 : cross access interdit
    forbidden = job_repo.get_by_id(user_a.id, job_b.id)

    print("Cross access result:", forbidden)

    if forbidden is not None:
        print("❌ FAIL: user A can access job B")
    else:
        print("✅ OK: isolation respected")



    # Provider A
    provider_repo.upsert(
        ProviderConfig(
            id=str(uuid.uuid4()),
            user_id=user_a.id,
            provider_name="realdebrid",
            is_enabled=True,
            is_default=True,
            encrypted_api_key="KEY_A",
            account_expires_at=None,
            created_at=now(),
            updated_at=now(),
        )
    )

    # Provider B
    provider_repo.upsert(
        ProviderConfig(
            id=str(uuid.uuid4()),
            user_id=user_b.id,
            provider_name="realdebrid",
            is_enabled=True,
            is_default=True,
            encrypted_api_key="KEY_B",
            account_expires_at=None,
            created_at=now(),
            updated_at=now(),
        )
    )

    print(provider_repo.get(user_a.id, "realdebrid").encrypted_api_key)
    print(provider_repo.get(user_b.id, "realdebrid").encrypted_api_key)

    dest_repo.upsert(
        DestinationConfig(
            id=str(uuid.uuid4()),
            user_id=user_a.id,
            destination_name="links_only",
            is_enabled=True,
            is_default=True,
            config_json="{}",
            created_at=now(),
            updated_at=now(),
        )
    )

    dest_repo.upsert(
        DestinationConfig(
            id=str(uuid.uuid4()),
            user_id=user_b.id,
            destination_name="local",
            is_enabled=True,
            is_default=True,
            config_json='{"base_path": "/tmp/user_b"}',
            created_at=now(),
            updated_at=now(),
        )
    )

    dest_a = dest_repo.get(user_a.id, "links_only")
    dest_b = dest_repo.get(user_b.id, "local")
    forbidden_dest = dest_repo.get(user_a.id, "local")

    print(dest_a.destination_name, dest_a.config_json)
    print(dest_b.destination_name, dest_b.config_json)
    print("Forbidden destination access:", forbidden_dest)

    if forbidden_dest is not None:
        print("❌ FAIL: user A can access user B destination")
    else:
        print("✅ OK: destination isolation respected")

if __name__ == "__main__":
    main()
