# Create necessary directories if they don't exist
$directories = @(
    "src\models",
    "src\utils",
    "src\models\__pycache__"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Move files from models to src/models
$modelFiles = Get-ChildItem -Path "models" -File -Recurse
foreach ($file in $modelFiles) {
    $destination = $file.FullName.Replace("models", "src\\models")
    Move-Item -Path $file.FullName -Destination $destination -Force
    Write-Host "Moved: $($file.FullName) -> $destination"
}

# Move files from utils to src/utils (if utils exists)
if (Test-Path "utils") {
    $utilFiles = Get-ChildItem -Path "utils" -File -Recurse
    foreach ($file in $utilFiles) {
        $destination = $file.FullName.Replace("utils", "src\\utils")
        Move-Item -Path $file.FullName -Destination $destination -Force
        Write-Host "Moved: $($file.FullName) -> $destination"
    }
}

# Create __init__.py files if they don't exist
$initFiles = @(
    "src\__init__.py",
    "src\models\__init__.py",
    "src\utils\__init__.py"
)

foreach ($file in $initFiles) {
    if (-not (Test-Path $file)) {
        New-Item -ItemType File -Path $file -Force | Out-Null
        Write-Host "Created: $file"
    }
}

Write-Host "\nFile reorganization complete!"
