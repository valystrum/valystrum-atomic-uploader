# Changelog

Each release is a tag of this repository. Pin the tag in your download URL (see the README).

## v1.0.1 (2026-10-29)

- After an upload, the last count is named for what it is: the waiting runs, this upload's or earlier ones, that a
  detection confirmed in this upload's check. v1.0.0 said "confirmed by a detection so far", which read as a total
  for the log.
- The README says when a run reads pending and when "ran, detection not confirmed", that a detection a later sync
  brings in still confirms it, and which alerts each EDR's connector takes in.

## v1.0.0 (2026-10-29)

The first public release, for Valystrum v0.21.0 and later.

- Needs Breach and attack simulation on your organisation's plan (Gold, Enterprise and Partner include it) and the
  upload secret, which an owner or admin issues on Settings, Atomic Red Team uploads. It is shown once; issuing it
  again rotates it and the old one stops working at once, and once it is revoked every upload is refused. A suspended
  organisation's uploads are refused too.
- Uploads an Invoke-AtomicRedTeam execution log (the default CSV or Attire JSON) to your organisation's
  `/api/v1/<org>/bas/runs` endpoint; each test run becomes a run on its ATT&CK technique in Valystrum, with the host it
  ran on. The run waits for your EDR, connected in Valystrum, to report that technique (or its parent, or one of its
  sub-techniques) on that host inside your detection window after the run (30 minutes unless your organisation changed
  it). CrowdStrike Falcon, Wazuh and Microsoft Defender for Endpoint alerts name the host; Microsoft Sentinel and
  Splunk alerts name none yet, so they do not confirm a run. Hosts are compared case-blind, a DNS name by its first
  label. A detection marks the run detected, and prevented only when the EDR itself reported blocking it (Falcon and
  Microsoft Defender report a block, Wazuh does not). Until something confirms it the run reads pending, and "ran,
  detection not confirmed" once the window has closed; a detection timed inside the window that a later sync brings in
  still confirms it, and an assessor can confirm it on the technique's page. A log sent twice records each run once.
- Upload the log soon after the tests: a run more than 14 days old is recorded but never matched to a detection
  automatically, and an entry timed more than ten minutes ahead of Valystrum's clock is skipped.
- After an upload it prints how many runs it recorded, how many were already on record, and how many waiting runs,
  this upload's or earlier ones, a detection confirmed during this upload (a run confirmed earlier is not counted
  again, so a log sent again can print 0). It then prints each entry it could not read with the reason (no UTC
  execution time, no ATT&CK technique id, no test GUID, no host name, or a time in the future), up to 50 an upload. An
  entry that cannot be read is skipped, never guessed.
- With the uploader, Valystrum runs nothing in your network and holds no access to it: the script only calls out to
  Valystrum. From each entry Valystrum keeps its time, technique, test number and name, host, test GUID and exit code;
  the log itself, an Attire log's test output included, is read and not stored.
- `-Campaigns` lists your organisation's campaigns, whether each is due (a manual campaign never is), and the
  `Invoke-AtomicTest` line for each of its tests, a parent technique's sub-techniques' tests included. `-Platform` is
  optional: without it every platform's tests are listed. Its values are Atomic Red Team's (`windows`, `linux`,
  `macos`, `containers`, `iaas`, `azure-ad`, `office-365`, `google-workspace`); another value lists no tests. The test
  numbers are those of the Atomic Red Team index Valystrum holds (its commit is on Settings, Atomic Red Team uploads),
  and each line names its test: check it against your own atomics folder before you run it.
- `-CampaignId <id>` (the id `-Campaigns` prints) marks a campaign run with the uploaded log. The id must be one of
  your organisation's campaigns, or the upload is refused and nothing is recorded. The campaign is marked run with the results the log's runs had
  after the correlation, those still waiting for a detection included, so it reads as not due until its next interval.
- Every request is signed afresh (`X-CS-Signature: t=<unix seconds>,v1=<HMAC-SHA256>`) with the upload secret read
  from the `VALYSTRUM_ATOMIC_SECRET` environment variable, never from a parameter. The signed time must be within five
  minutes of Valystrum's clock, and each signature is accepted once.
- Limits: 5 MB a request, counted on the JSON body that carries the log (somewhat larger than the log file), 500 test
  runs an upload, 30 requests a minute for your organisation and 150 a minute from one address.
- A refusal stops the script; it does not retry. Valystrum's answer gives the reason: a signature that does not
  verify, is stale or was already used (401); a plan without Breach and attack simulation, or a suspended organisation
  (403); a campaign that is not yours (404); an upload over the limits (413); an empty log or a file that is not an
  execution log (400 or 422); or too many requests (429). Run it again: it signs afresh, and runs already recorded
  are not recorded twice.
- https only, and no redirect is followed.
- Windows PowerShell 5.1, or PowerShell 7 on Windows, Linux or macOS; nothing else to install. The script is not
  code-signed: on Windows the `AllSigned` and `Restricted` execution policies refuse it, and `RemoteSigned` refuses a
  copy marked as downloaded until you have read it and run `Unblock-File .\valystrum-atomic.ps1`. Licensed under the
  Apache License 2.0.
