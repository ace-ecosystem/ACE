rule local : unittest
{
    strings:
        $ = "Received:"
    condition:
        any of them
}
