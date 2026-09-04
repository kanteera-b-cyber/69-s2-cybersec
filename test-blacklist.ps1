$ErrorActionPreference = "Stop"
$base = "http://localhost:1337"

function PostJson($url, $body) {
  $json = $body | ConvertTo-Json -Compress
  return Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Body $json
}

# Admin login
Write-Host "=== Admin Login ==="
$adminLogin = PostJson "$base/admin/login" @{ email = "<EMAIL>"; password = "<CHANGE-ME>"; rememberMe = $false }
Write-Host "Admin login status: token present = $($null -ne $adminLogin.data.token)"
$adminToken = $adminLogin.data.token

# First admin profile request (should succeed)
Write-Host "`n=== Admin Profile Request 1 (should succeed) ==="
$headers = @{ Authorization = "Bearer $adminToken" }
try {
  $r1 = Invoke-RestMethod -Uri "$base/admin/users/me" -Method Get -Headers $headers
  Write-Host "Request 1 OK. User: $($r1.data.firstname)"
} catch {
  Write-Host "Request 1 FAILED: $($_.Exception.Message)"
}

# Second admin profile request with SAME token (should be blacklisted)
Write-Host "`n=== Admin Profile Request 2 with SAME token (should be rejected) ==="
try {
  $r2 = Invoke-RestMethod -Uri "$base/admin/users/me" -Method Get -Headers $headers
  Write-Host "Request 2 SUCCEEDED (UNEXPECTED!)"
} catch {
  $status = $_.Exception.Response.StatusCode.value__
  Write-Host "Request 2 rejected with status $status (expected)"
}

# User login
Write-Host "`n=== User Login ==="
$userLogin = PostJson "$base/api/auth/local" @{ identifier = "<EMAIL>"; password = "<CHANGE-ME>" }
Write-Host "User login jwt present = $($null -ne $userLogin.jwt)"
$userToken = $userLogin.jwt

# First user profile request
Write-Host "`n=== User Profile Request 1 (should succeed) ==="
$uheaders = @{ Authorization = "Bearer $userToken" }
try {
  $r3 = Invoke-RestMethod -Uri "$base/api/users/me" -Method Get -Headers $uheaders
  Write-Host "User Request 1 OK. User: $($r3.username)"
} catch {
  Write-Host "User Request 1 FAILED: $($_.Exception.Message)"
}

# Second user profile request with SAME token (should be blacklisted)
Write-Host "`n=== User Profile Request 2 with SAME token (should be rejected) ==="
try {
  $r4 = Invoke-RestMethod -Uri "$base/api/users/me" -Method Get -Headers $uheaders
  Write-Host "User Request 2 SUCCEEDED (UNEXPECTED!)"
} catch {
  $status = $_.Exception.Response.StatusCode.value__
  Write-Host "User Request 2 rejected with status $status (expected)"
}
