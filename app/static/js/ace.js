// Alert Correlation Engine
// 

function escape_html(unsafe) {
    if (unsafe === null)
        return 'null';

    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function copy_to_clipboard(str) {
    var $temp = $("<input>");
    $("body").append($temp);
    $temp.val(str).select();
    document.execCommand("copy");
    $temp.remove();
}

$(document).ready(function() {
    $("#event-form").on("submit", function(e) {
        e.preventDefault();
        var event_name_re = /^[a-zA-Z0-9-. ]+$/;
        event_name = $("#event_name").val();
        if (event_name != "" && ! event_name_re.test(event_name)) {
            alert("Event names can only have the characters a-Z A-Z 0-9 - . and space.");
            return;
        }

        this.submit();
    });
});

function toggleNewEventDialog() {
  if (document.getElementById("option_NEW").checked) {
    document.getElementById("new_event_dialog").style.display = 'block';
  }
  else {
    document.getElementById("new_event_dialog").style.display = 'none';
  }
}

function toggleNewCampaignInput() {
  if (document.getElementById("campaign_id").value == 'NEW') {
    document.getElementById("new_campaign").style.display = 'block';
  }
  else {
    document.getElementById("new_campaign").style.display = 'none';
  }
}

function new_malware_option() {
  var index = new Date().valueOf()
  $.ajax({
    dataType: "html",
    url: 'new_malware_option',
    data: {index: index},
    success: function(data, textStatus, jqXHR) {
      $('#new_event_dialog').append(data);
    },
    error: function(jqXHR, textStatus, errorThrown) {
      alert("DOH: " + textStatus);
    }
  });
}

// This function is called from the "Send to.." modal dialog
$(document).on('click', '#btn-send-to-send', function() {
  // append the selected host to the formData
  var selectedHost = $("#selected-host").val()
  sendToDatastore.formData["hostname"] = selectedHost;
  
  // send a request to the API
  $.post(sendToDatastore.url, sendToDatastore.formData)
    .fail(function (data, textStatus, jqXHR) {
      alert("Action failed: " + textStatus);
    })
    .always(function () {
      $('#send-to-modal').modal('hide');
  });
});

function remove_malware_option(index) {
  var element = document.getElementById("malware_option_" + index);
  element.parentNode.removeChild(element);
}

function malware_selection_changed(index) {
  var element = document.getElementById("malware_selection_" + index);
  if (element.value == 'NEW') {
    document.getElementById("new_malware_info_" + index).style.display = 'block';
  }
  else {
    document.getElementById("new_malware_info_" + index).style.display = 'none';
  }
}

let placeholder_src = {
    "email_conversation": "Sender@example.com",
    "email_delivery": "<Message-ID>",
    "ipv4_conversation": "ex. 1.1.1.1",
    "ipv4_full_conversation": "ex. 1.1.1.1:1010"
};
let placeholder_dst = {
    "email_conversation": "Recipient@example.com",
    "email_delivery": "Recipient@example.com",
    "ipv4_conversation": "ex. 2.2.2.2",
    "ipv4_full_conversation": "ex. 2.2.2.2:2020"
};

window.localStorage.setItem('placeholder_src', JSON.stringify(placeholder_src));
window.localStorage.setItem('placeholder_dst', JSON.stringify(placeholder_dst));

