# Build the app image and push it to ECR, tagged with the git short SHA and "latest".
# Usage: .\scripts\push_image.ps1   then: terraform -chdir=infra/app apply -var image_tag=<tag>
$ErrorActionPreference = 'Stop'

function Invoke-Native([scriptblock]$Command) {
    # PowerShell 5.1 treats any stderr output of a native program as an error; docker writes
    # progress to stderr. So merge stderr and judge by the exit code only.
    $ErrorActionPreference = 'Continue'
    & $Command 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { throw "Failed (exit code $LASTEXITCODE): $Command" }
}

Set-Location (Split-Path -Parent $PSScriptRoot)
if (git status --porcelain) { throw "Uncommitted changes: commit first, the tag must match the code." }
$tag = (git rev-parse --short HEAD).Trim()
$repoUrl = terraform -chdir=infra/base output -raw ecr_repository_url
$region = terraform -chdir=infra/base output -raw aws_region
$registry = $repoUrl.Split('/')[0]
Write-Host "Pushing ${repoUrl}:$tag"

# The pipe runs in cmd: PowerShell 5.1 adds a BOM to piped text, and ECR rejects the token.
Invoke-Native { cmd /c "aws ecr get-login-password --region $region | docker login --username AWS --password-stdin $registry" }
# linux/amd64 for t3 instances. No provenance/SBOM: ECR scan on push skips multi-manifest images.
Invoke-Native { docker build --pull --platform linux/amd64 --provenance=false --sbom=false --build-arg "APP_VERSION=$tag" -t "${repoUrl}:$tag" -t "${repoUrl}:latest" . }
Invoke-Native { docker push "${repoUrl}:$tag" }
Invoke-Native { docker push "${repoUrl}:latest" }

Write-Host "Done. Deploy with: terraform -chdir=infra/app apply -var image_tag=$tag" -ForegroundColor Green
