param (
[string]$u = ""
)

$USER = switch ($u)
{
    root
    {
        "root"
    }

    default
    {
        "ace"
    }
}

docker exec -it -u $USER ace-dev /bin/bash -il

