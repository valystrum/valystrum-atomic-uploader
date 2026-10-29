# Valystrum Atomic Red Team uploader

Uploads an [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) execution log to
Valystrum, signed with your organisation's upload secret, and reads your organisation's campaigns and which of them are
due. You run [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) tests on your own test hosts; with the
uploader, Valystrum runs nothing in your network and holds no access to it. The script only sends: the signed log, and
signed reads of your campaigns.

This project is licensed under the Apache License 2.0 ([LICENSE](LICENSE)), Copyright 2026 Valystrum B.V.; the
Valystrum platform it calls is not. Releases are listed in [CHANGELOG.md](CHANGELOG.md).

> **Status, 2026-10-29.** Written for Valystrum v0.21.0, live on app.valystrum.io.

## Before you start

- Breach and attack simulation is part of the Gold plan and above (Gold, Enterprise and Partner). On another plan
  Settings does not list Atomic Red Team uploads, no upload secret can be issued, and an upload signed with an earlier
  secret is refused (HTTP 403).
- An owner or admin of your organisation issues the upload secret.
- On each test host: Invoke-AtomicRedTeam, Windows PowerShell 5.1 or PowerShell 7 (Windows, Linux or macOS), and
  outbound https to app.valystrum.io. The script needs nothing else.
- A connected EDR (see [What happens to a run](#what-happens-to-a-run)), if you want runs confirmed without an
  assessor.

## Get it

The uploader is one PowerShell script, `valystrum-atomic.ps1`. Download it at a release tag, so what runs on your test
hosts changes only when you choose, and read it before you run it:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/valystrum/valystrum-atomic-uploader/v1.0.1/valystrum-atomic.ps1 -OutFile valystrum-atomic.ps1
```

The script is not code-signed, so an execution policy of `AllSigned` or `Restricted` refuses it however it arrived. A
browser marks a file it downloads, and `RemoteSigned` refuses an unsigned script with that mark; once you have read it,
`Unblock-File .\valystrum-atomic.ps1` clears the mark. `Invoke-WebRequest` in Windows PowerShell 5.1, as above, leaves
no mark.

The script only reads the log, signs it, sends it and prints the answer. Valystrum reads the log, matches runs to
detections and builds the campaign lists, so those change with the platform and need no new download. Move your
pinned tag when [CHANGELOG.md](CHANGELOG.md) lists a release you want.

## Set up

1. In Valystrum, Settings, Atomic Red Team uploads: an owner or admin issues the upload secret. It is shown once,
   with the endpoint it signs for. There is one upload secret for your organisation, and every test host uses it.
   Issuing it again rotates it: the old secret stops working at once, so give the new one to each host. An owner or
   admin can also revoke it on the same page, on any plan (where Settings does not list the page, open
   `/next/settings/bas-uploads`); uploads signed with it are refused from then on.
2. On the test host, give the uploader the secret through the environment, never on the command line:

   ```powershell
   $env:VALYSTRUM_ATOMIC_SECRET = "<the upload secret>"
   ```

   Keep the test host's clock in sync (NTP). The signature must be within five minutes of Valystrum's clock, an entry
   logged more than ten minutes ahead of it is skipped, and the detection window starts at the time the log gives each
   test, so a clock that runs ahead can place a run after the detection it caused.

3. Run the tests with an execution logger. Attire JSON carries each test's output; the default CSV is smaller:

   ```powershell
   Invoke-AtomicTest T1059.001 -TestNumbers 1 -LoggingModule "Attire-ExecutionLogger" -ExecutionLogPath C:\AtomicRuns\attire.json
   ```

   Each entry needs its execution time in UTC, its ATT&CK technique id, its test GUID and the host name; the test
   number, name and exit code are kept when the log has them. A CSV log without the "Execution Time (UTC)",
   "Technique", "Hostname" and "GUID" columns, or a JSON file that is not Attire, is refused whole. An entry that lacks
   one of these, or whose time is more than ten minutes ahead of Valystrum's clock, is skipped, and the rest are
   recorded.

4. Upload the log:

   ```powershell
   ./valystrum-atomic.ps1 -Endpoint https://app.valystrum.io/api/v1/<org>/bas/runs -LogPath C:\AtomicRuns\attire.json
   ```

   `<org>` is your organisation's slug, the name in your Valystrum URLs. The settings page shows the whole endpoint
   with the secret, and again under How the uploader runs: copy it from there.

   The uploader prints how many runs it recorded, how many were already on record and how many waiting runs a
   detection confirmed (this upload's or earlier ones), then each entry it skipped with the reason (the first 50). A
   log uploaded twice records each run once, so an appended CSV log can be sent whole every time, until it holds more
   than 500 test runs or the upload passes 5 MB. Then the whole upload is refused and nothing in it is recorded, so
   start a new log file (one a day, or one a campaign) before it gets there. The 5 MB counts the request body, in
   which the log is escaped as JSON, so a log file a little under 5 MB can still be too large.

## What happens to a run

Each test the log records becomes a run on its ATT&CK technique on the BAS / ATT&CK page, with the host it ran on.
It waits for your EDR, connected in Valystrum, to report that technique (or its parent, or one of its
sub-techniques) on that host inside your detection window: Microsoft Defender for Endpoint, Wazuh or CrowdStrike
Falcon today (Microsoft Sentinel and Splunk alerts name no host yet, so they do not confirm a run). A detection marks
the run detected, and prevented only when the EDR itself reported blocking it: Falcon and Defender report a block,
Wazuh does not. A run nothing confirms reads "pending" while its detection window is open, then "ran, detection not
confirmed" until a detection a later sync brings in confirms it (below), or an assessor confirms it on the
technique's page. Nothing is guessed.

Only an alert its connector takes in can confirm a run. The Falcon connector takes in only alerts still new when it
syncs, so one already set in progress or closed is missed; the Defender connector never takes in informational or
resolved alerts; and the Wazuh connector skips alerts below the level set on the connection (7 by default).
Valystrum keeps one Wazuh finding per rule and agent, so a rule that has already alerted on that agent may not confirm
a later test.

The host is matched by name, ignoring case and comparing only the part before the first dot (an IP address is
compared whole), so `WS01` in the log matches `ws01.corp.example` in your EDR. If the EDR names the host some other
way, the run waits for an assessor.

The detection window is 30 minutes unless an owner or admin changes it on the BAS / ATT&CK page (1 to 1,440 minutes),
and it is counted from the time the log gives the test. Your EDR's alerts reach Valystrum when its connector syncs
(every two hours for CrowdStrike Falcon, hourly for Microsoft Defender for Endpoint and Wazuh), so a run can read
"ran, detection not confirmed" for a while. Every upload and every sync of a connected EDR checks the waiting runs of
the last 14 days again, and a detection whose own time falls inside the window still confirms its run. Upload a log
within 14 days of its tests: an older run is recorded but never matched to a detection automatically.

Of each test run, Valystrum keeps the technique, the test's GUID, number and name, the host name, the time it ran and
its exit code. The log itself is read and not stored: whatever else it carries, an Attire log's test output included,
crosses to Valystrum but is not kept. If a test's output could hold something you would rather not send, use the
default CSV logger.

An uploaded run on its own raises no finding and fails no control: only a detection, or an assessor's confirmation,
gives it a result on its technique. Settings, Atomic Red Team uploads counts the runs uploaded, those awaiting a
detection and those a detection confirmed, and says when the last upload arrived.

## Campaigns

A campaign set up on the BAS / ATT&CK page is read, not pushed:

```powershell
./valystrum-atomic.ps1 -Endpoint https://app.valystrum.io/api/v1/<org>/bas/runs -Campaigns -Platform windows
```

It lists each campaign, whether it is due, and the `Invoke-AtomicTest` line for each of its Atomic tests on your
platform (a parent technique's sub-techniques' tests included), each followed by the test's name. Without `-Platform`
the list holds every platform's tests; the platforms are `windows`, `linux`, `macos`, `containers`, `iaas`,
`google-workspace`, `azure-ad` and `office-365`; another value lists no tests. Upload the resulting log with
`-CampaignId <id>` to mark the campaign run; an id that is not one of your organisation's campaigns is refused, and
nothing is recorded.

The test numbers come from Atomic Red Team at the commit shown on Settings, Atomic Red Team uploads (Test index;
`atomicIndexCommit` in the answer). If your atomics folder is at another commit, a number can name another test, so
check the name printed after each line (the answer also gives each test's GUID, which `Invoke-AtomicTest -TestGuids`
accepts).

A weekly campaign is due seven days after its last run and a monthly one after 30; one never run is due at once, and a
manual one never is. Unless your organisation connected a simulator of its own on the BAS / ATT&CK page, Valystrum
runs nothing on that schedule: you run the tests and upload the log.

## The request

| | |
|---|---|
| Upload | `POST <endpoint>` with `{ "log": "<the log as written>", "campaignId": "<optional>" }` |
| Campaigns | `GET <endpoint>?platform=<windows, linux, macos, ...>`, or without a query for every platform |
| Signature | `X-CS-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 over "<t>.<payload>">`: the payload is the JSON body for an upload and the query string without `?` for campaigns (empty when there is none) |
| Freshness | the signed time within five minutes of the server's clock; each signature is accepted once, so sign every request afresh |
| Limits | 5 MB and 500 test runs an upload (the 5 MB counts the JSON body); 30 signed requests a minute for your organisation, all test hosts together, and 150 requests a minute from one address, signed or not |
| Answer | JSON, below; a refusal is `{ "ok": false, "error": "<what to do>" }` with a status from [When a request is refused](#when-a-request-is-refused) |

An upload answers:

```json
{ "ok": true, "data": { "format": "attire", "recorded": 1, "duplicates": 0, "confirmed": 0,
  "skipped": [{ "entry": 2, "reason": "no test GUID" }] } }
```

`format` is `csv` or `attire`, and `skipped` lists the first 50 entries that could not be read. `confirmed` counts
every waiting run of your organisation that this upload's check confirmed, earlier uploads' included, so it is not a
total for this log.

A campaign read answers:

```json
{ "ok": true, "data": {
  "campaigns": [{ "id": "<campaign id>", "name": "Weekly execution", "schedule": "weekly", "due": true,
    "lastRunAt": null,
    "techniques": [{ "mitreId": "T1059.001", "tests": [{ "technique": "T1059.001", "number": 1, "name": "Mimikatz",
      "guid": "f3132740-55bc-48c4-bcc0-758a459cd027", "platforms": ["windows"] }] }] }],
  "detectionWindowMinutes": 30, "atomicIndexCommit": "<the index commit>" } }
```

`schedule` is `weekly`, `monthly` or `manual`, and `lastRunAt` is an ISO time or `null`.

## When a request is refused

The uploader stops on a refusal, with Valystrum's answer in its error, and does not retry; a scheduled task sees it
fail. Run it again once the cause is fixed: it signs afresh, and runs already recorded are not recorded twice.

| Answer | What to do |
|---|---|
| 401 "The signature does not verify" | One answer for all of these, so it tells nobody which organisations exist: the secret in `VALYSTRUM_ATOMIC_SECRET` is wrong, rotated or revoked; no secret was ever issued; or `<org>` in the endpoint is not your organisation's slug. Copy the endpoint from the settings page |
| 401 "The signed time is more than five minutes from the server's clock" | Set the test host's clock right (NTP) |
| 401 "That signature was already used" | Each signature is accepted once: the same request sent twice in one second repeats it. Run the uploader again |
| 403 "not on this organisation's plan" | Breach and attack simulation needs the Gold plan or above |
| 403 "This organisation is suspended" | Uploads are refused until the organisation is restored |
| 404 "That campaign is not this organisation's" | Check `-CampaignId` against the `-Campaigns` list. Nothing was recorded |
| 400 | The body is not `{ "log": ..., "campaignId": ... }` JSON, or the log file is empty |
| 413 | Over 5 MB or 500 test runs: split the log, or start a new one |
| 422 | The file is not an Invoke-AtomicRedTeam execution log (the default CSV or Attire JSON), or holds only blank space; the answer says which |
| 429 | More than 30 signed requests a minute for your organisation, or 150 from one address: wait a minute |

## Support

Questions, and what your uploads show: [support@valystrum.com](mailto:support@valystrum.com), or **Contact support**
in Valystrum's Help menu. Report a security problem in this script to
[security@valystrum.com](mailto:security@valystrum.com).
