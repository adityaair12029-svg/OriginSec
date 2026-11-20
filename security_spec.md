# OriginSec Firestore Security Specification

## 1. Data Invariants
1. Every user document in `/users/{uid}` can only be read, created, or updated by the authenticated user matching `uid` (with `email_verified == true`), and `role` must be `'user'` on creation and immutable on client updates.
2. Every scan in `/scans/{scanId}` must belong to `request.auth.uid` (`ownerUid == request.auth.uid`), require `authorizedConfirmed == true`, and enforce immutable `ownerUid`, `scanId`, and `startedAt`. Terminal scans (`completed`, `failed`, `cancelled`) cannot transition back to `running` or modify core timestamps/ownership.
3. Every finding in `/scanFindings/{findingId}` must reference an existing parent `/scans/{scanId}` owned by `request.auth.uid` (Master Gate) and enforce `ownerUid == request.auth.uid` on both `get` and `list`.
4. Every integration in `/integrations/{integrationId}`, verified domain in `/verifiedDomains/{domainId}`, monitoring target in `/monitoringTargets/{targetId}`, and backup status in `/backupStatus/{recordId}` is strictly isolated to `ownerUid == request.auth.uid`.
5. Every monitoring event in `/monitoringEvents/{eventId}` must reference an existing parent `/monitoringTargets/{targetId}` owned by `request.auth.uid` and enforce `ownerUid == request.auth.uid`.
6. All document IDs must satisfy `isValidId(id)` (`^[a-zA-Z0-9_\-]+$`, max 128 chars), all strings have `.size()` upper bounds, and all creation/update timestamps match `request.time`.

## 2. The "Dirty Dozen" Attack Payloads (Must Return PERMISSION_DENIED)
1. **Unauthenticated read**: Unauthenticated `get(/scans/scan_1)` -> DENIED.
2. **Cross-user read (IDOR)**: User B calls `get(/scans/scan_owned_by_user_A)` -> DENIED.
3. **Blanket list scraping**: User B calls `list(/scans)` without `where('ownerUid', '==', userB)` -> DENIED.
4. **Privilege escalation on user creation**: User A creates `/users/userA` with `{ role: 'owner' }` -> DENIED.
5. **Privilege escalation on user update**: User A updates `/users/userA` changing `role` from `'user'` to `'owner'` -> DENIED.
6. **Shadow / Ghost field injection**: User A creates `/scans/scan_1` with `{ ..., isVerifiedBypass: true }` -> DENIED via `keys().hasOnly(...)`.
7. **Identity spoofing**: User A creates `/scans/scan_1` with `ownerUid: 'userB'` -> DENIED.
8. **Orphaned finding write**: User A creates `/scanFindings/f_1` with `scanId: 'nonexistent_scan'` or `scanId` owned by User B -> DENIED via Master Gate `get()`.
9. **Resource poisoning (oversized ID / string)**: User A creates `/scans/<2000-char-id>` or sets `targetUrl` > 2048 chars -> DENIED.
10. **Timestamp forgery**: User A creates `/scans/scan_1` with `startedAt` set to a past client timestamp instead of `request.time` -> DENIED.
11. **Terminal state tampering**: User A attempts to change a `completed` scan's `status` back to `running` or overwrite `ownerUid` -> DENIED.
12. **Unverified email write**: Authenticated user with `email_verified == false` attempts to write to `/scans/scan_1` -> DENIED.
