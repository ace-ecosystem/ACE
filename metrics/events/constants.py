"""Constants for event metrics."""

# The core ACE specific killchain dispositions that
# mean an event should be considered an incident.
# If you add more, add them to the end of the list or
# extend this list where ever you need to.
INCIDENT_DISPOSITIONS = [ 'EXPLOITATION',
                          'INSTALLATION',
                          'COMMAND_AND_CONTROL',
                          'EXFIL',
                          'DAMAGE'
                        ]

# Database query for getting events between two dates
#  and pulling relevant details from the various table mappings
# Allows for reduction by list of company ids
EVENT_DB_QUERY = """SELECT 
                        events.id, 
                        events.creation_date as 'Date', events.name as 'Event', 
                        GROUP_CONCAT(DISTINCT malware.name SEPARATOR ', ') as 'Malware', 
                        GROUP_CONCAT(DISTINCT IFNULL(malware_threat_mapping.type, 'UNKNOWN') SEPARATOR ', ') 
                            as 'Threat', GROUP_CONCAT(DISTINCT alerts.disposition SEPARATOR ', ') as 'Disposition', 
                        events.vector as 'Delivery Vector', 
                        events.prevention_tool as 'Prevention', 
                        GROUP_CONCAT(DISTINCT company.name SEPARATOR ', ') as 'Company', 
                        count(DISTINCT event_mapping.alert_id) as '# Alerts' 
                    FROM events 
                        JOIN event_mapping 
                            ON events.id=event_mapping.event_id 
                        JOIN malware_mapping 
                            ON events.id=malware_mapping.event_id 
                        JOIN malware 
                            ON malware.id=malware_mapping.malware_id 
                        JOIN company_mapping 
                            ON events.id=company_mapping.event_id 
                        JOIN company 
                            ON company.id=company_mapping.company_id 
                        LEFT JOIN malware_threat_mapping 
                            ON malware.id=malware_threat_mapping.malware_id 
                        JOIN alerts 
                            ON alerts.id=event_mapping.alert_id 
                    WHERE 
                        events.status='CLOSED' AND events.creation_date 
                        BETWEEN %s AND %s {}{}
                    GROUP BY events.name, events.creation_date, event_mapping.event_id 
                    ORDER BY events.creation_date
                """