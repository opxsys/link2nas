# Next UI Regression Checklist

Short manual checklist to run after each significant Next UI refactor, and before merge or publication.

## How to use

Run this checklist after each Next UI page refactor, before merging a large UI change, and before publishing a release candidate.

The goal is not exhaustive QA. The goal is to catch obvious regressions in critical user flows.

## 1. Auth / public flows

- [ ] Login works.
- [ ] Logout works.
- [ ] Expired or invalid token redirects to `/login` without showing protected content.
- [ ] Fresh install setup creates the first administrator and logs in.
- [ ] Password reset with a valid link works.
- [ ] Password reset with an already-used or expired link shows a clear invalid-link message before showing the form.
- [ ] Magic login with an invalid, expired, or already-used link shows a clear invalid-link message.

## 2. Jobs / providers

- [ ] Fresh install with 0 provider does not show the `New Job` button.
- [ ] Direct access to `/jobs/new` with 0 provider redirects to Jobs with a clear provider notice.
- [ ] Settings provider deep-link `/settings?section=providers` opens the Providers section.
- [ ] Bad provider API key shows a clean message, not raw AllDebrid / RealDebrid text.
- [ ] Bad torrent shows a clean message, not Cloudflare HTML or `HTTP 502`.
- [ ] Expected provider errors return JSON with HTTP `422`, not `502`.

## 3. Job flows

- [ ] Links-only job creation works.
- [ ] Failed job state displays cleanly.
- [ ] `Start` on a failed or created job displays clean provider errors when relevant.
- [ ] `Restart` on a failed or cancelled job displays clean provider errors when relevant.
- [ ] Ready jobs still show usable links and relevant actions.
- [ ] Completed jobs still show usable links and relevant actions.
- [ ] Cancelled jobs display coherent actions.

## 4. Settings

- [ ] Provider creation works.
- [ ] Provider edit works.
- [ ] Provider API key test works.
- [ ] Provider enable / disable works.
- [ ] Provider default selection works.
- [ ] Destination creation works.
- [ ] Destination edit works.
- [ ] Destination test works.
- [ ] Destination enable / disable works.
- [ ] Destination default selection works.
- [ ] API key creation shows the secret one time only.
- [ ] API key revoke works.
- [ ] API key delete works.

## 5. Layout / shell

- [ ] Dashboard loads without raw `Missing X-Api-Key header`.
- [ ] Mobile sidebar opens and closes.
- [ ] Theme toggle works.
- [ ] Language selector still works on auth pages.

## Notes

If a checklist item fails, fix it before continuing the next page refactor.
