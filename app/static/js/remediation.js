function remediation_selection(alert_uuids=null, targets=null) {
    // displays the remediation selection dialog that allows the analyst to select which targets to remove/restore
    data = { };

    if (alert_uuids !== null) {
        data['alert_uuids'] = JSON.stringify(alert_uuids);
    } else {
        // are we specifying specific targets?
        if (targets !== null) {
            data['targets'] = JSON.stringify(targets);
        } else {
            // otherwise we load all the possible targets for this alert
            data['alert_uuids'] = JSON.stringify([ current_alert_uuid ]);
        }
    }
    
    $('#remediation-selection-modal').modal('show');
    $('#remediation-selection-body').html('loading data...');

    $.ajax({
        'url': query_remediation_targets_url, // <-- set in app/templates/base.html
        'data': data,
        'dataType': 'json',
        'error': function(jqXHR, textStatus, errorThrown) {
            alert("ERROR: " + textStatus);
        },
        'method': 'POST',
'success': function(data, textStatus, jqXHR) {
            var html = '<table class="table table-striped">\
<tr>\
    <td>&nbsp;</td>\
    <td>Type</td>\
    <td>Target</td>\
</tr>'
            for (var key in data) {
                var observable_type = data[key]['type'];
                var observable_value = data[key]['value'];
                var observable_value_b64 = btoa(observable_value);
                var remediation_type = data[key]['remediation_type'];
                var remediation_key = data[key]['remediation_key'];
                var remediation_key_b64 = btoa(remediation_key);
                var remediation_history = data[key]['history'];

                var in_progress = false;
                var remediated = false;
                if (remediation_history.length > 0) {
                    var last_status = remediation_history[0]['status'];
                    if (last_status == 'IN_PROGRESS' || last_status == 'NEW') {
                        in_progress = true;
                    } else if (last_status == 'COMPLETED') {
                        if (remediation_history[0]['action'] == 'remove') {
                            remediated = true;
                        }
                    }
                }

                html += '<tr';
                if (remediated) {
                    html += ' class="success">';
                } else if (in_progress) {
                    html += ' class="warning">';
                } else {
                    html += '>';
                }

                html += '<td><input type="checkbox" ';

                // if the email has not been remediated then we default to it being selected
                if (! remediated && ! in_progress)
                    html += ' checked ';

                html += 'id="cb_remediation_' + remediation_key_b64
                     + '" data-r-type="' + remediation_type
                     + '" data-r-key="' + remediation_key_b64
                     + '" data-o-type="' + observable_type
                     + '" data-o-value="' + observable_value_b64
                     + '"></td>'
                     + '<td>' + escape_html(remediation_type) + '</td>'
                     + '<td>' + escape_html(observable_value) + '</td>'
                     + '</tr>';
            }

            html += '</table>';
            $('#remediation-selection-body').html(html);
        }
    });
}

function execute_remediation_selection(action) {
    var targets = [];
    $('input:checked[id^=cb_remediation_]').each(function(i, e) {
        targets.push({'remediation_type': e.dataset.rType,
                      'remediation_key_b64': e.dataset.rKey, 
                      'observable_type': e.dataset.oType, 
                      'observable_value_b64': e.dataset.oValue});
    });
    blocking = $('#cb-do-it-now').is(':checked');
    remediate_targets(action, targets, blocking);
}

function remediate_targets(action, targets, blocking=true) {
    /* executes the given remediation action (restore or remove) against the given targets
       optional blocking parameter can be set to false to execute remediations in background */

    $('#remediation-selection-modal').modal('hide');
    $('#remediation-activity-body').html('remediating ' + targets.length + ' targets...');
    $('#remediation_activity_modal').modal('show');

    var request = $.ajax({
        'data': {
            'json_request': JSON.stringify({
                'action': action,
                'targets': targets,
                'blocking': blocking
            })
        },
        'dataType': 'json',
        'error': function(jqXHR, textStatus, errorThrown) {
            $('#remediation-activity-body').html(textStatus);
        },
        'method': 'POST',
        'url': remediate_targets_url, // <-- set in app/templates/base.html
        'success': function(data, textStatus, jqXHR) {
            var html = '<ul>\n';
            for (var i = 0; i < data.length; i++) {
                html += '<li>' + escape_html(data[i]['key']) + ': ' + (blocking ? escape_html(data[i]['result']) : 'scheduled') + '\n';
            }
            html += '</ul>\n'
            $('#remediation-activity-body').html(html);
        }
    });

    $('#btn-remediation-activity-cancel').click(function(e) {
        request.abort();
        $('#remediation_activity_modal').modal('hide');
    });
}

$(document).ready(function() {
    $('#btn-remediation').click(function(e) {
        remediation_selection();
    });

    $('#btn-remediation-selection-remove').click(function(e) {
        execute_remediation_selection('remove');
    });

    $('#btn-remediation-selection-restore').click(function(e) {
        execute_remediation_selection('restore');
    });
});

function remediate_target(remediation_type, remediation_key_b64, observable_type, observable_value_b64) {
    remediate_targets('remove', [{
        'remediation_type': remediation_type,
        'remediation_key_b64': remediation_key_b64,
        'observable_type': observable_type,
        'observable_value_b64': observable_value_b64
    }], true);
}

function restore_target(remediation_type, remediation_key_b64, observable_type, observable_value_b64) {
    remediate_targets('restore', [{
        'remediation_type': remediation_type,
        'remediation_key_b64': remediation_key_b64,
        'observable_type': observable_type,
        'observable_value_b64': observable_value_b64
    }], true);
}

function remediate_emails(alert_uuids=null, message_ids=null) {

    // query these message_ids or alert_uuids to see what emails are available
    // provide a popup with all of the emails with this message_id (for this company)
    // click to rememdiate

    data = { };
    if (alert_uuids != null)
        data['alert_uuids'] = JSON.stringify(alert_uuids);
    if (message_ids != null)
        data['message_ids'] = JSON.stringify(message_ids);
    
    $.ajax({
        'url': query_message_ids_url, // <-- set in app/templates/base.html
        'data': data,
        'dataType': 'json',
        'error': function(jqXHR, textStatus, errorThrown) {
            alert("ERROR: " + textStatus);
        },
        'method': 'POST',
        'success': function(data, textStatus, jqXHR) {
            var html = '<table class="table table-striped">\
<tr>\
    <td>&nbsp;</td>\
    <td>From</td>\
    <td>To</td>\
    <td>Subject</td>\
</tr>'
            for (var source in data) {
                for (var archive_id in data[source]) {
                    var sender = data[source][archive_id]['sender'];
                    var recipient = data[source][archive_id]['recipient'];
                    var subject = data[source][archive_id]['subject'];
                    var remediated = data[source][archive_id]['remediated'];
                    var remediation_history = data[source][archive_id]['remediation_history'];

                    var in_progress = false;
                    if (remediation_history.length > 0) {
                        var last_status = remediation_history[remediation_history.length - 1]['status'];
                        if (last_status == 'IN_PROGRESS' || last_status == 'NEW') {
                            in_progress = true;
                        }
                    }

                    // sometimes embedded emails do not have recipient
                    // and you can't remediated an embedded email anyways
                    if (recipient == null) continue;

                    html += '<tr';
                    if (remediated) {
                        html += ' class="success">';
                    } else if (in_progress) {
                        html += ' class="warning">';
                    } else {
                        html += '>';
                    }

                        html += '\
    <td><input type="checkbox" ';

                        // if the email has not been remediated then we default to it being selected
                        if (! remediated && ! in_progress) 
                            html += ' checked ';

                        html += 'id="cb_archive_id_' + archive_id + '_source_' + source + '"></td>\
    <td>' + sender + '</td>\
    <td>' + recipient + '</td>\
    <td>' + subject + '</td>\
</tr>';
                }
            }

            html += '</table>';

            $('#email-remediation-body').html(html);
            $('#btn-email-remediation').show();
            $('#btn-email-restore').show();
            $('#div-cb-do-it-now').show();
            $('#btn-email-remediation-done').text("Chicken Out");
            $('#email_remediation_label').text("Email Remediation");

            function execute(action) {
                var request_data = {};
                $('input:checked[id^=cb_archive_id_]').each(function(i, e) {
                    request_data[e.id] = '1';
                });

                request_data['action'] = action;
                request_data['do_it_now'] = $('#cb-do-it-now').is(':checked');
                request_data['alert_uuids'] = JSON.stringify(alert_uuids);

                $('#email-remediation-body').html("Sending request...");
                $('#btn-email-remediation').hide();
                $('#btn-email-restore').hide();
                $('#div-cb-do-it-now').hide();
                $('#btn-email-remediation-done').hide();

                $.ajax({
                    'data': request_data,
                    'dataType': 'json',
                    'error': function(jqXHR, textStatus, errorThrown) {
                        alert("ERROR: " + textStatus);
                    },
                    'method': 'POST',
                    'url': remediate_emails_url, // <-- set in app/templates/base.html
                    'success': function(data, textStatus, jqXHR) {
                        var html = '<table class="table table-striped">\
<tr>\
    <td>Email</td>\
    <td>Result</td>\
    <td>Details</td>\
</tr>';
                        for (var archive_id in data) {
                            var email = data[archive_id]['recipient'];
                            var result_text = data[archive_id]['result_text'];
                            var result_success = data[archive_id]['result_success'];

                            html += '\
<tr>\
    <td>' + email + '</td>\
    <td>' + result_success + '</td>\
    <td>' + result_text + '</td>\
</tr>';

                        }
                        html += '</table>';
                        $('#email_remediation_label').text("Remediation Results");
                        $('#email-remediation-body').html(html);
                        $('#btn-email-remediation').hide();
                        $('#btn-email-restore').hide();
                        $('#div-cb-do-int-now').hide();
                        $('#btn-email-remediation-done').text("Fantastic");
                        $('#btn-email-remediation-done').show();
                        $('#btn-email-remediation').off('click');
                        $('#btn-email-remediation').click(function(e) {
                            e.preventDefault();
                            $('#email_remediation_modal').modal({
                                show: 'false'
                            });
                        });
                    },
                });
            }

            $('#btn-email-restore').off('click');
            $('#btn-email-restore').click(function(e) {
                e.preventDefault()
                execute(action='restore');
            });

            $('#btn-email-remediation').off('click');
            $('#btn-email-remediation').click(function(e) {
                e.preventDefault();
                execute(action='remove');
            });

            $('#email_remediation_modal').modal({
                show: 'true'
            });
        },
    });
}
