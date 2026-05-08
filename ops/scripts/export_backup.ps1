param(
  [string]$ApiBase = "http://127.0.0.1:8000/api/v1",
  [string]$Username = $env:DEMO_ADMIN_USERNAME,
  [string]$Password = $env:DEMO_ADMIN_PASSWORD,
  [string]$OutputPath = "..\..\ops\backups\backup-snapshot.json"
)

if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($Password)) {
  throw "Set DEMO_ADMIN_USERNAME and DEMO_ADMIN_PASSWORD in backend/.env or pass -Username and -Password explicitly."
}

$loginBody = @{
  username = $Username
  password = $Password
} | ConvertTo-Json

$loginResponse = Invoke-RestMethod -Method Post -Uri "$ApiBase/auth/login" -Body $loginBody -ContentType "application/json"
$token = $loginResponse.access_token

$headers = @{
  Authorization = "Bearer $token"
}

$snapshot = Invoke-RestMethod -Method Get -Uri "$ApiBase/admin/backup/snapshot" -Headers $headers
$snapshot | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputPath -Encoding utf8

Write-Host "Backup snapshot exported to $OutputPath"
