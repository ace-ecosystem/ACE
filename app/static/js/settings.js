setting_id = null;
parent_id = null;

$(document).ready(function() {
    // recreate collapse state
    $('[id^="setting_children_"]').each(function(index) {
        id = $(this).attr('id').substring(17)
        shown = $.cookie('setting_shown_' + id);
        if (shown != null && shown == 'yes') {
            $('#setting_children_' + id).toggle();
            $('#setting_chevron_' + id).toggleClass('glyphicon-chevron-down');
            $('#setting_chevron_' + id).toggleClass('glyphicon-chevron-right');
        }
    });

    // recreate scroll position
    scroll = $.cookie("manage_settings_scroll") 
    if (scroll != null) {
        $('#content_area').scrollTop(scroll);
    }
});

function toggle(id) {
    shown = $.cookie('setting_shown_' + id);
    if (shown != null && shown == 'yes') {
        $.cookie('setting_shown_' + id, 'no')
    } else {
        $.cookie('setting_shown_' + id, 'yes')
    }
    $('#setting_children_' + id).toggle();
    $('#setting_chevron_' + id).toggleClass('glyphicon-chevron-down');
    $('#setting_chevron_' + id).toggleClass('glyphicon-chevron-right');
}

function request(method, url, data, success) {
    $.ajax({
        type: method,
        url: url,
        dataType: "html",
        contentType: "application/json",
        data: JSON.stringify(data),
        processData: false,
        success: success,
        error: function(jqXHR, textStatus, errorThrown) {
            alert(jqXHR.responseText);
        }
    });
}

function add_setting(event, id) {
    request('POST', '/ace/settings/add', {id: id}, function(result, textStatus, jqXHR) {
        setting_id = null;
        parent_id = id;
        $('#setting_modal_body').html(result);
        $('#setting_modal').modal('show');
    });
    event.stopPropagation();
}

function edit_setting(event, id, p_id) {
    request('POST', '/ace/settings/edit', {id: id, parent_id: p_id}, function(result, textStatus, jqXHR) {
        setting_id = id;
        parent_id = p_id;
        $('#setting_modal_body').html(result);
        $('#setting_modal').modal('show');
    });
    event.stopPropagation();
}

function reload_page(result, textStatus, jqXHR) {
    $.cookie("manage_settings_scroll", $('#content_area').scrollTop());
    window.location.replace(window.location.href);
}

function save_setting() {
    $('#setting_modal').modal('hide');
    data = {
        'id': setting_id,
        'parent_id': parent_id,
        'key': $('[name="setting_key"]').val(), 
        'children': {}
    };
    if ($('[name="setting_value"]').length) {
        data['value'] = $('[name="setting_value"]').val();
    } else {
        data['value'] = null;
    }
    $('[name^="setting_child_"]').each(function(index) {
        data['children'][$(this).attr('name').substring(14)] = $(this).val();
    });
    request('PUT', window.location.href, data, reload_page);
}

function save_setting_value(form, id, key, input) {
    data = {
        'id': id,
        'parent_id': null,
        'key': key,
        'value': $(input).val(),
        'children': {}
    };
    request('PUT', window.location.href, data, null);
}

function remove_setting(event, id, key) {
    if (confirm('Delete ' + key + '?')) {
        request('DELETE', window.location.href, {id: id}, reload_page);
    }
    event.stopPropagation();
}

function check(id) {
    $(id).find(':submit').click();
}

function import_settings() {
    input = document.createElement('input');
    input.type = 'file';
    input.onchange = e => {
       file = e.target.files[0];
       reader = new FileReader();
       reader.readAsText(file,'UTF-8');
       reader.onload = readerEvent => {
          data = JSON.parse(readerEvent.target.result);
          request('PUT', '/ace/settings/import', data, reload_page);
       }
    }
    input.click();
}
