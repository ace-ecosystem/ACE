ALTER TABLE
    `alerts` 
MODIFY COLUMN
    `disposition` enum(
        'FALSE_POSITIVE',
        'IGNORE',
        'UNKNOWN',
        'REVIEWED',
        'GRAYWARE',
        'POLICY_VIOLATION',
        'RECONNAISSANCE',
        'WEAPONIZATION',
        'DELIVERY',
        'EXPLOITATION',
        'INSTALLATION',
        'COMMAND_AND_CONTROL',
        'EXFIL',
        'DAMAGE',
        'INSIDER_DATA_CONTROL',
        'INSIDER_DATA_EXFIL'
    )
;
