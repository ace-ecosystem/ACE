[CmdletBinding()]
param(
  [switch]$f,
  [switch]$s
)

# Get Full Reset & Reset SSL arguments

if ($f) {
    $FULL_RESET = "-r"
}

if ($s) {
    $SSL_RESET = "-r"
}

# Initialize docker if doing full reset

if ($f) {
    python .\bin\initialize_docker.py
}

# Stop and remove any stale ace containers still running
docker-compose -f .\docker-compose-dev.yml stop
docker container rm ace-dev > $null 2>&1
docker container rm ace-db-dev > $null 2>&1
docker volume rm ace-redis-dev > $null 2>&1
docker volume rm ace-data-dev > $null 2>&1
docker volume rm ace-db-dev > $null 2>&1
#docker volume rm ace-home-dev > $null 2>&1

# Run script to build docker images, exit on fail
& .\bin\build_docker_dev_images.ps1
$BUILD_SUCCESSFUL = $?
if (-Not $BUILD_SUCCESSFUL) {
    Write-Host -NoNewLine "ERROR: docker images failed to build"
    exit 1
}

# Spin up ace containers
docker-compose -f .\docker-compose-dev.yml up -d

# WINDOWS ONLY: Set permissions as necessary
docker exec -it -u root ace-dev /bin/bash -c 'chown -R ace:ace /opt/ace/data'
docker exec -it -u root ace-dev /bin/bash -c 'chown -R ace:ace /home/ace'

# Install ACE within container
docker exec -it -u root ace-dev /bin/bash -c "docker/provision/ace/install $FULL_RESET $SSL_RESET -t DEVELOPMENT"

# Wait for the database to come up
$COUNT = 0
Write-Host -NoNewLine "waiting for database"
while ($true) {
    if (docker logs ace-db-dev 2>&1 | Select-String -Q "mysqld: ready for connections." 2>&1) {
        if (docker logs ace-db-dev 2>&1 | Select-String -Q 'DATABASE BUILD OK' 2>&1)
        {
            break
        }
        if ($COUNT -gt 60){
            Write-Host "Database is taking unusually long to connect"
            Write-Host  "=============================================="
            Write-Host
            Write-Host  "are you making changes to the schema?"
            Write-Host  'Ctrl+C and use the following command to investigate'
            Write-Host
            Write-Host  'docker logs ace-db-dev'
            Write-Host
            Write-Host  "=============================================="
            $COUNT = 0
        }
    }

    Write-Host -NoNewLine "."
    Start-Sleep -s 2
    $COUNT = $COUNT + 2
}


# Add dev user
docker exec -it -u ace ace-dev /bin/bash -it -c 'ace user add --password=analyst analyst analyst@localhost'

# Execute any additional setup scripts
$files = Get-ChildItem -Path ".\docker\provision\ace\site" | Where-Object { $_.Name -ne "README"} | Sort-Object
ForEach ($file in $files) {
    if ($file -like "*_container.sh") {
        Write-Output("executing $file in container...")

        # if the file name has _root_ in it then we execute it as root
        $user = "ace"
        if ($file -like "*_root_*") {
            Write-Output("executing $file as root...")
            $user = "root"
        }

        docker exec -it -u $user ace-dev /bin/bash -il "docker/provision/ace/site/$file"
    } elseif ($file -like "*.ps1")  {
        Write-Output("executing $file on host...")
        & ".\docker\provision\ace\site\$file"
    }
}

# Done!
Write-Output("reset complete; added default user 'analyst' password 'analyst'")
