# Script to organize the project structure

# Create directories
$directories = @(
    "src\siem\core",
    "src\siem\services",
    "src\siem\models",
    "src\siem\api",
    "src\siem\utils",
    "src\edr",
    "src\dlp",
    "src\hips",
    "src\nips",
    "src\ndr",
    "src\fim",
    "config\development",
    "config\production",
    "config\testing",
    "tests\unit",
    "tests\integration",
    "tests\e2e",
    "docs\api",
    "docs\architecture",
    "docs\deployment",
    "infrastructure\docker",
    "infrastructure\kubernetes",
    "infrastructure\terraform",
    "data\logs",
    "data\db",
    "data\backups",
    "tools\lint",
    "tools\docs",
    "tools\test"
)

# Create all directories
foreach ($dir in $directories) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Write-Host "Created directory: $dir"
}

# Move files to their new locations (example - adjust paths as needed)
$fileMappings = @{
    # Core SIEM components
    "SIEM\core\*.py" = "src\siem\core\"
    "SIEM\services\*.py" = "src\siem\services\"
    "SIEM\models\*.py" = "src\siem\models\"
    "SIEM\api\*.py" = "src\siem\api\"
    "SIEM\utils\*.py" = "src\siem\utils\"
    
    # Security modules
    "edr\*.py" = "src\edr\"
    "dlp\*.py" = "src\dlp\"
    "hips\*.py" = "src\hips\"
    "nips\*.py" = "src\nips\"
    "ndr\*.py" = "src\ndr\"
    "fim\*.py" = "src\fim\"
    
    # Configuration
    "config\*" = "config\development\"
    
    # Tests
    "tests\*" = "tests\unit\"
    "testing_development\tests\*" = "tests\"
    
    # Data
    "data\*" = "data\db\"
    "data_logs\*" = "data\logs\"
    "db_backups\*" = "data\backups\"
    "logs\*" = "data\logs\siem\"
}

# Move files according to mappings
foreach ($mapping in $fileMappings.GetEnumerator()) {
    $source = $mapping.Key
    $destination = $mapping.Value
    
    if (Test-Path $source) {
        Move-Item -Path $source -Destination $destination -Force -ErrorAction SilentlyContinue
        Write-Host "Moved $source to $destination"
    } else {
        Write-Host "Source not found: $source"
    }
}

Write-Host "`nReorganization complete!"
Write-Host "Please review the changes and update any import statements in your Python files."
