import time


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log_job(job_id: str, step: str, message: str = ""):
    print(f"{_now()} [JOB {job_id}] [{step}] {message}".strip())


def log_error(job_id: str, step: str, message: str):
    print(f"{_now()} [JOB {job_id}] [ERROR:{step}] {message}")


def log_system(step: str, message: str = ""):
    print(f"{_now()} [SYSTEM] [{step}] {message}".strip())