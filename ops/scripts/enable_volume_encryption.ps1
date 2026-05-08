param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[A-Za-z]$")]
  [string]$DriveLetter,

  [switch]$UsedSpaceOnly,
  [switch]$SkipHardwareTest
)

$mountPoint = "${DriveLetter}:"

if (-not (Get-Command Enable-BitLocker -ErrorAction SilentlyContinue)) {
  throw "BitLocker cmdlets are unavailable. Run on Windows Pro/Enterprise with BitLocker feature enabled."
}

if (-not (Test-Path $mountPoint)) {
  throw "Drive $mountPoint was not found."
}

$protectors = Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
if ($protectors.ProtectionStatus -eq "On") {
  Write-Host "BitLocker is already enabled on $mountPoint"
  return
}

$recoveryProtector = Add-BitLockerKeyProtector -MountPoint $mountPoint -RecoveryPasswordProtector

$enableArgs = @{
  MountPoint = $mountPoint
  EncryptionMethod = "XtsAes256"
  RecoveryPasswordProtector = $true
}

if ($UsedSpaceOnly.IsPresent) {
  $enableArgs["UsedSpaceOnly"] = $true
}

if ($SkipHardwareTest.IsPresent) {
  $enableArgs["SkipHardwareTest"] = $true
}

Enable-BitLocker @enableArgs | Out-Null

$recoveryPassword = $recoveryProtector.RecoveryPassword
Write-Host "BitLocker enable command issued for $mountPoint"
Write-Host "Recovery password (store securely): $recoveryPassword"
