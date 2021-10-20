$http_proxy=""
$https_proxy=""
if (Test-Path "proxy_settings.txt")
{
    $http_proxy = Get-Content "proxy_settings.txt" -Raw
    $https_proxy = Get-Content "proxy_settings.txt" -Raw
}

docker image build -f Dockerfile.ace-base -t ace-base:latest --build-arg http_proxy="$http_proxy" --build-arg https_proxy="$https_proxy" .
docker image build -f Dockerfile.ace-dev -t ace-dev:latest .
