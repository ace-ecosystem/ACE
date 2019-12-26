SELECT
    QIDNAME(qid) as "Event Name",
    payload,
    deviceTime,
    endTime,
    startTime,
    "Bricata-MSG",
    CONCAT(sourceip, '_', destinationip) AS "ipv4_conversation",
    *
FROM
    events
WHERE
    LOGSOURCENAME(logsourceid) ILIKE '%bricata%'
START '<O_START>'
STOP '<O_STOP>'
