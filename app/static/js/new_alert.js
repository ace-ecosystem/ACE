$(document).ready(function() {
    $('input[name="new_alert_insert_date"]').datetimepicker({
      showSecond: true,
      dateFormat: 'mm-dd-yy',
      timeFormat: 'HH:mm:ss'
    });

    $('input[name="observables_times_0"]').datetimepicker({
      showSecond: true,
      dateFormat: 'mm-dd-yy',
      timeFormat: 'HH:mm:ss'
    });
});

function new_alert_observable() {
  var index = new Date().valueOf()
  $.ajax({
    dataType: "html",
    url: 'new_alert_observable',
    data: {index: index},
    success: function(data, textStatus, jqXHR) {
      $('#new_alert_observables').append(data);
      $('input[name="observables_times_' + index + '"]').datetimepicker({
        showSecond: true,
        dateFormat: 'mm-dd-yy',
        timeFormat: 'HH:mm:ss'
      });
    },
    error: function(jqXHR, textStatus, errorThrown) {
      alert("DOH: " + textStatus);
    }
  });
}

function new_alert_observable_type_changed(index) {
  var type_input = document.getElementById("observables_types_" + index);
  var value_input = document.getElementById("observables_values_" + index);
  if (type_input.value === 'file') {
    if (value_input.type !== 'file') {
      value_input.parentNode.removeChild(value_input);
      $('#new_alert_observable_value_' + index).append('<input class="form-control" type="file" name="observables_values_' + index + '" id="observables_values_' + index + '" value="">');
    }
  } else if (['email_conversation', 'email_delivery', 'ipv4_conversation', 'ipv4_full_conversation'].includes(type_input.value)) {
    value_input.parentNode.removeChild(value_input);
    let placeholder_src = JSON.parse(window.localStorage.getItem("placeholder_src"));
    let placeholder_dst = JSON.parse(window.localStorage.getItem("placeholder_dst"));
    $('#new_alert_observable_value_' + index).append('<span class="form-inline" style="display: contents" id="observables_values_' + index + '" >' +
        '<input class="form-control" style="width:auto" type="text" name="observables_values_' + index + '_A" id="observables_values_' + index + '_A" value="" placeholder="' + placeholder_src[type_input.value] + '"> to ' +
        '<input class="form-control" style="width:auto" type="text" name="observables_values_' + index + '_B" id="observables_values_' + index + '_B" value="" placeholder="' + placeholder_dst[type_input.value] + '" title="Multiple values should be comma-separated"></span>');
  } else {
    value_input.parentNode.removeChild(value_input);
    $('#new_alert_observable_value_' + index).append('<input class="form-control" type="text" name="observables_values_' + index + '" id="observables_values_' + index + '" value="">');
  }
}

function new_alert_remove_observable(index) {
  var element = document.getElementById("new_alert_observable_" + index);
  element.parentNode.removeChild(element);
}
