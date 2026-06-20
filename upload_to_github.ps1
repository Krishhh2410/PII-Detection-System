# PowerShell script to upload PII Detection System to GitHub
# Run this script to push the code to your GitHub profile

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PII Detection System - GitHub Uploader" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if git is installed
try {
    $gitVersion = git --version
    Write-Host "✓ Git found: $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Git is not installed. Please install Git first:" -ForegroundColor Red
    Write-Host "  https://git-scm.com/download/win" -ForegroundColor Yellow
    exit 1
}

# Set the project path
$projectPath = "c:\Users\Jainam\Downloads\PII-Detection-Sanitization-System-main\PII-Detection-Sanitization-System-main\MineD"
Set-Location $projectPath

Write-Host ""
Write-Host "Project location: $projectPath" -ForegroundColor Gray
Write-Host ""

# Check if already a git repo
if (Test-Path ".git") {
    Write-Host "✓ Git repository already initialized" -ForegroundColor Green
} else {
    Write-Host "→ Initializing git repository..." -ForegroundColor Yellow
    git init
    Write-Host "✓ Repository initialized" -ForegroundColor Green
}

# Configure git (if not already configured)
$gitUser = git config user.name
$gitEmail = git config user.email

if (-not $gitUser) {
    Write-Host ""
    Write-Host "→ Configuring Git user name..." -ForegroundColor Yellow
    git config user.name "jainamkamdar512-prog"
}

if (-not $gitEmail) {
    Write-Host ""
    Write-Host "→ Configuring Git user email..." -ForegroundColor Yellow
    $email = Read-Host "Enter your email address"
    git config user.email $email
}

# Create .gitignore
Write-Host ""
Write-Host "→ Creating .gitignore..." -ForegroundColor Yellow
$gitignoreContent = @"
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Database
*.db
*.sqlite
*.sqlite3

# Uploads and sensitive data
backend/uploads/
backend/sanitized/
*.key
*.pem

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
"@

$gitignoreContent | Out-File -FilePath ".gitignore" -Encoding UTF8
Write-Host "✓ .gitignore created" -ForegroundColor Green

# Add all files
Write-Host ""
Write-Host "→ Adding files to git..." -ForegroundColor Yellow
git add .
Write-Host "✓ Files added" -ForegroundColor Green

# Check status
Write-Host ""
Write-Host "→ Git status:" -ForegroundColor Gray
git status --short

# Commit
Write-Host ""
Write-Host "→ Creating commit..." -ForegroundColor Yellow
git commit -m "PII Detection & Sanitization System v2.0

Features:
- Address detection and masking
- Real-time text analysis with PII highlighting
- Compare sanitization modes (Mask/Redact/Tokenize)
- Batch text analysis
- Interactive dashboard with analytics
- PII trends and user activity tracking
- Modern dark theme UI
- Enhanced admin dashboard with charts"

Write-Host "✓ Commit created" -ForegroundColor Green

# Instructions for GitHub
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NEXT STEPS:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Go to https://github.com/new" -ForegroundColor White
Write-Host "2. Create a new repository (e.g., 'PII-Detection-System')" -ForegroundColor White
Write-Host "3. Do NOT initialize with README (we already have files)" -ForegroundColor White
Write-Host ""
Write-Host "4. Then run these commands:" -ForegroundColor Yellow
Write-Host ""
Write-Host "   git remote add origin https://github.com/jainamkamdar512-prog/YOUR_REPO_NAME.git" -ForegroundColor Green
Write-Host "   git branch -M main" -ForegroundColor Green
Write-Host "   git push -u origin main" -ForegroundColor Green
Write-Host ""
Write-Host "5. Enter your GitHub username and Personal Access Token when prompted" -ForegroundColor White
Write-Host ""
Write-Host "To create a Personal Access Token:" -ForegroundColor Gray
Write-Host "   https://github.com/settings/tokens" -ForegroundColor Blue
Write-Host ""
