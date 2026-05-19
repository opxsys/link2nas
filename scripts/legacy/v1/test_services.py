import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "backend"))

from storage.db import Database
from repositories.user_repository import UserRepository
from repositories.job_repository import JobRepository
from repositories.provider_config_repository import ProviderConfigRepository
from repositories.destination_config_repository import DestinationConfigRepository
from services.user_context import UserContext
from services.job_service import JobService
from services.provider_config_service import ProviderConfigService
from services.destination_config_service import DestinationConfigService

from models.user import User

import uuid
from datetime import UTC, datetime


DB_PATH = ROOT_DIR / "data" / "link2nas_v2.sqlite3"


def now() -> str:
    return datetime.now(UTC).isoformat()


def main() -> None:
    db = Database(str(DB_PATH))

    user_repo = UserRepository(db)

    job_service = JobService(JobRepository(db))
    provider_service = ProviderConfigService(ProviderConfigRepository(db))
    destination_service = DestinationConfigService(DestinationConfigRepository(db))

    run_id = uuid.uuid4().hex[:8]

    user_a = User(
        id=str(uuid.uuid4()),
        email=f"svc_a_{run_id}@test.com",
        display_name="Service User A",
        role="user",
        is_active=True,
        created_at=now(),
        updated_at=now(),
    )

    user_b = User(
        id=str(uuid.uuid4()),
        email=f"svc_b_{run_id}@test.com",
        display_name="Service User B",
        role="user",
        is_active=True,
        created_at=now(),
        updated_at=now(),
    )

    user_repo.create(user_a)
    user_repo.create(user_b)

    ctx_a = UserContext(user_id=user_a.id, role=user_a.role)
    ctx_b = UserContext(user_id=user_b.id, role=user_b.role)

    job_a = job_service.create_job(
        context=ctx_a,
        source_type="magnet",
        source_value="magnet_service_A",
        provider_name="realdebrid",
        destination_name="links_only",
    )

    job_b = job_service.create_job(
        context=ctx_b,
        source_type="magnet",
        source_value="magnet_service_B",
        provider_name="alldebrid",
        destination_name="local",
    )

    jobs_a = job_service.list_jobs(ctx_a)
    jobs_b = job_service.list_jobs(ctx_b)

    forbidden_job = job_service.get_job(ctx_a, job_b.id)

    provider_service.save_provider_config(
        context=ctx_a,
        provider_name="realdebrid",
        encrypted_api_key="SVC_KEY_A",
        is_enabled=True,
        is_default=True,
    )

    provider_service.save_provider_config(
        context=ctx_b,
        provider_name="realdebrid",
        encrypted_api_key="SVC_KEY_B",
        is_enabled=True,
        is_default=True,
    )

    provider_a = provider_service.get_provider_config(ctx_a, "realdebrid")
    provider_b = provider_service.get_provider_config(ctx_b, "realdebrid")

    destination_service.save_destination_config(
        context=ctx_a,
        destination_name="links_only",
        config_json="{}",
        is_enabled=True,
        is_default=True,
    )

    destination_service.save_destination_config(
        context=ctx_b,
        destination_name="local",
        config_json='{"base_path": "/tmp/service_user_b"}',
        is_enabled=True,
        is_default=True,
    )

    destination_a = destination_service.get_destination_config(ctx_a, "links_only")
    forbidden_destination = destination_service.get_destination_config(ctx_a, "local")

    print(f"Service User A jobs: {len(jobs_a)}")
    print(f"Service User B jobs: {len(jobs_b)}")
    print("Forbidden job access:", forbidden_job)
    print("Provider A key:", provider_a.encrypted_api_key)
    print("Provider B key:", provider_b.encrypted_api_key)
    print("Destination A:", destination_a.destination_name, destination_a.config_json)
    print("Forbidden destination access:", forbidden_destination)

    assert len(jobs_a) >= 1
    assert len(jobs_b) >= 1
    assert forbidden_job is None
    assert provider_a.encrypted_api_key == "SVC_KEY_A"
    assert provider_b.encrypted_api_key == "SVC_KEY_B"
    assert destination_a.destination_name == "links_only"
    assert forbidden_destination is None

    print("✅ OK: service layer isolation respected")


if __name__ == "__main__":
    main()
