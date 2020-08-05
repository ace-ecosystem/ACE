param (
[string]$f = ""
)

$RESET = switch ($f)
{
    r
    {
        "-r"
    }

    default
    {
        ""
    }
}

if ($RESET == "-r") {
    python .\bin\initialize_docker.py
}

docker-compose -f .\docker-compose-dev.yml stop
docker container rm ace-dev > $null 2>&1
docker container rm ace-db-dev > $null 2>&1
docker volume rm ace-data-dev > $null 2>&1
docker volume rm ace-db-dev > $null 2>&1
#docker volume rm ace-home-dev > $null 2>&1
& .\bin\build_docker_dev_images.ps1
docker-compose -f .\docker-compose-dev.yml up -d
docker exec -it -u root ace-dev /bin/bash -c 'chown -R ace:ace /opt/ace/data'
docker exec -it -u root ace-dev /bin/bash -c 'chown -R ace:ace /home/ace'
docker exec -it -u root ace-dev /bin/bash -c "docker/provision/ace/install $RESET -t DEVELOPMENT"

Write-Host -NoNewLine "waiting for database..."
while ($true) {
    docker exec -it -u ace ace-dev /bin/bash -it -c 'ace test-database-connections' > $null 2>&1
    if ($?) {
        Write-Host ""
        break
    }

    Write-Host -NoNewLine "."
    Start-Sleep -s 1
}

docker exec -it -u ace ace-dev /bin/bash -it -c 'ace user add --password=analyst analyst analyst@localhost'

$files = Get-ChildItem -Path ".\docker\provision\ace\site" | Where-Object { $_.Name -ne "README"} | Sort-Object
ForEach ($f in $files) {
    if ($f -like "*_container.sh") {
        Write-Output("executing $f in container...")
        docker exec -it -u ace ace-dev /bin/bash -il "docker/provision/ace/site/$f"
    } elseif ($f -like "*.ps1")  {
        Write-Output("executing $f on host...")
        & ".\docker\provision\ace\site\$f"
    }
}

docker exec -it -u ace ace-dev /bin/bash -it -c './bin/start-ace'

Write-Output("reset complete; added default user 'analyst' password 'analyst'")
