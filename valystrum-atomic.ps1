<#
.SYNOPSIS
  Uploads an Invoke-AtomicRedTeam execution log to Valystrum, signed with your
  organisation's upload secret, or reads the campaigns that are due.

.DESCRIPTION
  Copyright 2026 Valystrum B.V. Licensed under the Apache License, Version 2.0
  (see LICENSE beside this file).

  Runs on the test host that ran the Atomic Red Team tests (Windows PowerShell 5.1
  or PowerShell 7 on Windows, Linux or macOS). It sends the execution log as it is
  written (the default CSV or Attire JSON) to POST <Endpoint>; each test run
  becomes a run on the technique in Valystrum that waits for your EDR, connected
  in Valystrum, to report it on that host: Microsoft Defender for Endpoint, Wazuh
  or CrowdStrike Falcon today (Microsoft Sentinel and Splunk alerts name no host
  yet, so they do not confirm a run).
  With -Campaigns it reads GET <Endpoint>: the campaigns your organisation set
  up, whether each is due, and the Atomic tests of each technique for your
  platform. Nothing calls into your network: this script only
  sends.

  The secret is read from the VALYSTRUM_ATOMIC_SECRET environment variable, never
  from a parameter (a parameter lands in the shell history). Every request is
  signed afresh: X-CS-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 over
  "<t>.<payload>">, the payload the JSON body for an upload and the query string
  (without "?") for -Campaigns. The server accepts a signature once, within five
  minutes of its clock.

.EXAMPLE
  $env:VALYSTRUM_ATOMIC_SECRET = "<the upload secret>"
  Invoke-AtomicTest T1059.001 -TestNumbers 1 -LoggingModule "Attire-ExecutionLogger" -ExecutionLogPath C:\AtomicRuns\attire.json
  ./valystrum-atomic.ps1 -Endpoint https://app.valystrum.io/api/v1/<org>/bas/runs -LogPath C:\AtomicRuns\attire.json

.EXAMPLE
  ./valystrum-atomic.ps1 -Endpoint https://app.valystrum.io/api/v1/<org>/bas/runs -Campaigns -Platform windows
#>
[CmdletBinding(DefaultParameterSetName = "Upload")]
param(
  [Parameter(Mandatory = $true)] [string] $Endpoint,
  [Parameter(ParameterSetName = "Upload", Mandatory = $true)] [string] $LogPath,
  [Parameter(ParameterSetName = "Upload")] [string] $CampaignId,
  [Parameter(ParameterSetName = "Campaigns", Mandatory = $true)] [switch] $Campaigns,
  [Parameter(ParameterSetName = "Campaigns")] [string] $Platform
)

$ErrorActionPreference = "Stop"
$secret = $env:VALYSTRUM_ATOMIC_SECRET
if (-not $secret) { throw "Set VALYSTRUM_ATOMIC_SECRET to the upload secret from Settings, Atomic Red Team uploads." }
if (-not $Endpoint.StartsWith("https://")) { throw "The endpoint must use https: the log and its signature cross the internet." }
# No redirect is followed (-MaximumRedirection 0 below): Windows PowerShell would follow one to http, and a 307 resends the log.

function Get-Signature([string] $Payload) {
  $t = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $hmac = New-Object System.Security.Cryptography.HMACSHA256 (, [Text.Encoding]::UTF8.GetBytes($secret))
  try { $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$t.$Payload")) } finally { $hmac.Dispose() }
  $v1 = -join ($hash | ForEach-Object { $_.ToString("x2") })
  return "t=$t,v1=$v1"
}

if ($Campaigns) {
  $query = ""
  if ($Platform) { $query = "platform=" + [uri]::EscapeDataString($Platform.ToLowerInvariant()) }
  $uri = $Endpoint
  if ($query) { $uri = "$Endpoint`?$query" }
  $res = Invoke-RestMethod -Method Get -Uri $uri -MaximumRedirection 0 -Headers @{ "X-CS-Signature" = (Get-Signature $query) }
  foreach ($c in $res.data.campaigns) {
    $tests = @($c.techniques | ForEach-Object { $_.tests }).Count
    $state = if ($c.due) { "due" } else { "not due" }
    Write-Output ("{0} ({1}, {2}): {3} technique(s), {4} Atomic test(s), campaign id {5}" -f $c.name, $c.schedule, $state, @($c.techniques).Count, $tests, $c.id)
    foreach ($t in $c.techniques) { foreach ($x in $t.tests) { Write-Output ("  Invoke-AtomicTest {0} -TestNumbers {1}    # {2}" -f $x.technique, $x.number, $x.name) } }
  }
  return
}

$log = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $LogPath).ProviderPath)
$body = @{ log = $log }
if ($CampaignId) { $body.campaignId = $CampaignId }
$json = $body | ConvertTo-Json -Compress -Depth 3
$res = Invoke-RestMethod -Method Post -Uri $Endpoint -MaximumRedirection 0 -ContentType "application/json; charset=utf-8" -Body ([Text.Encoding]::UTF8.GetBytes($json)) -Headers @{ "X-CS-Signature" = (Get-Signature $json) }
Write-Output ("Recorded {0} run(s) from the {1} log; {2} already on record; {3} waiting run(s), this upload's or earlier ones, confirmed by a detection in this upload's check." -f $res.data.recorded, $res.data.format, $res.data.duplicates, $res.data.confirmed)
foreach ($s in $res.data.skipped) { Write-Output ("Skipped entry {0}: {1}" -f $s.entry, $s.reason) }
