# Providers and Destinations — Developer Guide

This document explains how providers and destinations work in Link2NAS, and how to add a new one without scattering type definitions across the codebase.

---

## Overview

**Providers** are debrid/download services (Real-Debrid, AllDebrid). A user configures one or more provider profiles in Settings. Each profile holds an encrypted API key and a display name.

**Destinations** are send/storage targets (Synology NAS, local storage). A user configures one or more destination profiles in Settings. Each profile holds the connection parameters for that target, encrypted at rest when sensitive.

**Registry pattern.** The supported type keys are defined in two authoritative registry files:

- `backend/services_v2/provider_registry.py`
- `backend/services_v2/destination_registry.py`

Every other backend file (routes, services, factories) imports from these registries. Do not define new type sets inline in routes or service logic.

**Frontend.** Display labels and icons for the UI are centralized in:

- `frontend-next/src/lib/provider-types.ts`
- `frontend-next/src/lib/destination-types.ts`

Every Settings component that renders provider or destination types imports from these lib files.

---

## Adding a provider

### 1. Backend — client and provider classes

If the provider needs a new HTTP client, create it under:

```
backend/services_v2/providers/<name>_client.py
backend/services_v2/providers/<name>_provider.py
```

The provider class must implement the `Provider` protocol defined in `backend/services_v2/providers/base.py`.

### 2. Backend — register the type key

Open `backend/services_v2/provider_registry.py` and:

- Add the canonical type key (lowercase, no spaces) to `PROVIDER_KEYS`.
- Add a human-readable label to `PROVIDER_DISPLAY_NAMES`.
- Add an `if` branch to `build_provider()` that instantiates the client and provider, taking `token` and `settings` as inputs.

```python
# PROVIDER_KEYS
PROVIDER_KEYS: frozenset[str] = frozenset({"realdebrid", "alldebrid", "newprovider"})

# PROVIDER_DISPLAY_NAMES
PROVIDER_DISPLAY_NAMES: dict[str, str] = {
    "realdebrid": "Real-Debrid",
    "alldebrid": "AllDebrid",
    "newprovider": "New Provider",
}

# build_provider()
if provider_type == "newprovider":
    client = NewProviderClient(
        base_url=settings.NEWPROVIDER_BASE_URL,
        token=token,
        timeout=settings.NEWPROVIDER_TIMEOUT,
    )
    return NewProviderProvider(client)
```

### 3. Backend — settings

Add the base URL and timeout variables to `config.py` and document them in `docs/CONFIGURATION.md` under "Debrid providers". Add the corresponding entries to `.env.sample` and `.env.docker.*.sample`.

### 4. Backend — nothing else to change in the factory

`UserProviderFactory` calls `build_provider()` and re-raises `UnknownProviderError` on failure. No changes are usually needed there unless the new provider requires different runtime behavior.

`ProviderConfigService.save_provider_config()` uses `PROVIDER_KEYS` for validation and `PROVIDER_DISPLAY_NAMES` as the default profile name fallback. No changes needed there either.

### 5. Frontend

Open `frontend-next/src/lib/provider-types.ts` and add an entry to `PROVIDER_TYPES`:

```typescript
import { Cloud, Zap, SomeIcon } from 'lucide-react'

export const PROVIDER_TYPES: ProviderTypeDef[] = [
  { value: 'realdebrid', label: 'Real-Debrid', icon: Zap      },
  { value: 'alldebrid',  label: 'AllDebrid',   icon: Cloud    },
  { value: 'newprovider', label: 'New Provider', icon: SomeIcon },
]
```

`PROVIDER_LABEL` and `PROVIDER_ICON` are derived from this array — no other frontend change is needed.

### 6. Tests

Add test cases to `scripts/tests/unit/test_provider_registry.py`:

- Verify the new key is in `PROVIDER_KEYS`.
- Verify `PROVIDER_DISPLAY_NAMES` contains a non-empty string for it.
- Verify `build_provider("newprovider", token, settings)` returns the correct type.

### 7. Security check

- API keys must be encrypted before storing: `crypto.encrypt(plain_key)`.
- API keys must never appear in API responses. The serializers must only return `has_key: bool`, not the key itself.
- Review any new route that accepts or returns provider config to confirm this.

---

## Adding a destination

### 1. Backend — destination class

If the destination needs a new handler, create it under:

```
backend/services_v2/destinations/<name>_destination.py
```

The destination class must implement the `Destination` protocol defined in `backend/services_v2/destinations/base.py`. The required method is `send(output_links: list[dict]) -> dict`.

### 2. Backend — register the type key

Open `backend/services_v2/destination_registry.py` and:

- Add the canonical type key to `DESTINATION_KEYS`.
- Add a display name to `DESTINATION_DISPLAY_NAMES`.
- Add an alias to `DESTINATION_ALIAS_KEYS` only if a legacy key must be accepted for backward compatibility (example: `"nas"` → `"synology"`). Do not add aliases speculatively.

```python
DESTINATION_KEYS: frozenset[str] = frozenset({"synology", "local", "newdest"})

DESTINATION_DISPLAY_NAMES: dict[str, str] = {
    "synology": "Synology NAS",
    "local": "Local",
    "newdest": "New Destination",
}
```

`DESTINATION_ALL_KEYS` is derived automatically from `DESTINATION_KEYS | frozenset(DESTINATION_ALIAS_KEYS)`.

### 3. Backend — wire instantiation in the factory

Open `backend/services_v2/destination_factory.py` and add an `if` branch in the destination resolution flow after alias normalization:

```python
if destination_type == "newdest":
    try:
        cfg = json.loads(config.config_json or "{}")
    except Exception:
        raise UnknownDestinationError("Invalid newdest config")

    # decrypt secrets if needed
    crypto = current_app.config["CRYPTO_SERVICE_V2"]
    secret = crypto.decrypt(cfg.get("secret", ""))

    return ResolvedDestination(
        name="newdest",
        destination=NewDestination(
            host=cfg["host"],
            secret=secret,
        ),
        config=config,
    )
```

### 4. Backend — config validation

If the destination requires specific fields in `config_json`, add a validation branch in `_validate_destination_config()` inside `backend/routes_v2/destinations_support/validation.py`.

### 5. Frontend

Open `frontend-next/src/lib/destination-types.ts` and add an entry to `DESTINATION_TYPES`:

```typescript
export const DESTINATION_TYPES: DestinationTypeDef[] = [
  { value: 'synology', label: 'Synology NAS' },
  { value: 'local',    label: 'Local'         },
  { value: 'newdest',  label: 'New Destination' },
]
```

`DESTINATION_LABEL` is derived from this array. If the destination modal requires specific form fields, add a conditional section in `frontend-next/src/pages/Settings/DestinationModal.tsx`.

### 6. Tests

Add test cases to `scripts/tests/unit/test_destination_registry.py`:

- Verify the new key is in `DESTINATION_KEYS`.
- Verify `DESTINATION_DISPLAY_NAMES` contains a non-empty string for it.
- Verify `DESTINATION_ALL_KEYS` includes it.
- If a new alias was added, verify it resolves to the correct canonical key.

### 7. Connection test

If the destination supports a connectivity check, implement or wire the destination connectivity test according to the existing destination test flow and verify it is called by the test route in `backend/routes_v2/destinations_support/destination_test.py`.

---

## links_only

`links_only` is not a configured destination. It is a job execution mode: when selected, the job resolves unrestricted links but does not send them anywhere. There is no `DestinationConfig` record for it.

It is handled as a special case at the routing level (`request_validation.py`) and resolved to `LinksOnlyDestination` in the factory when no config is found and `allow_links_only=True`.

**Do not add `links_only` to `DESTINATION_KEYS`.** It is not a real destination type that users configure. Adding it to the registry would break validation logic that uses `DESTINATION_KEYS` to enumerate real, configurable destination types.

---

## Tests to run after a change

```bash
# Backend unit tests
python3 scripts/tests/unit/test_provider_registry.py
python3 scripts/tests/unit/test_destination_registry.py

# Python syntax check
python3 -m compileall app.py backend config.py

# Frontend
cd frontend-next
npm run type-check
npm run build
cd ..
```
