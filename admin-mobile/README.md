# MetalBear Admin

A basic React Native (Expo) app for managing a MetalBear PDS from iOS or
Android. Mirrors the web admin dashboard at `frontend/src/routes/admin`:
account lookup with takedown/deactivate/invite toggles, and invite code
listing/disabling.

## Auth

`com.atproto.admin.*` is gated by HTTP Basic auth against a fixed `admin`
username and the server's `METALBEAR_ADMIN_PASSWORD` — there's no bearer
session. The app asks for a PDS URL and admin password on launch and holds
both in memory only for the lifetime of the app (never persisted to disk),
the same "shouldn't outlive the session" posture as the web app's
`sessionStorage`-backed store. Signing out, or killing the app, clears it.

## Run

```sh
npm install
npm run ios      # or: npm run android
```

Requires Expo Go on the simulator/device, or `npx expo run:ios` /
`npx expo run:android` for a native dev build.

## Structure

- `src/api/pds.ts` — admin XRPC client (`getAccountInfo`, `getSubjectStatus`,
  `updateSubjectStatus`, `getInviteCodes`, `disableInviteCodes`,
  `enable/disableAccountInvites`, `resolveHandle`).
- `src/context/AdminSessionContext.tsx` — in-memory session state.
- `src/screens/` — `LoginScreen`, `DashboardScreen`.
- `src/components/` — `AccountLookup`, `InviteCodes`.
