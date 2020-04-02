//
// javascript functions for the analysis view
//

// this gets loaded when the document loads up
var current_alert_uuid = null;

$(document).ready(function() {
//$(window).load(function() {
// debugger; // FREAKING AWESOME
    $("#add_observable_type").change(function (e) {
        const observable_type = $("#add_observable_type option:selected").text();
        var add_observable_input = document.getElementById("add_observable_value");
        if (!['email_conversation', 'email_delivery', 'ipv4_conversation', 'ipv4_full_conversation', 'file'].includes(observable_type)) {
            add_observable_input.parentNode.removeChild(add_observable_input);
            $("#add_observable_value_content").append('<input type="text" class="form-control" id="add_observable_value" name="add_observable_value" value="" placeholder="Enter Value"/>');
        } else if (observable_type !== 'file') {
            add_observable_input.parentNode.removeChild(add_observable_input);
            let placeholder_src = JSON.parse(window.localStorage.getItem("placeholder_src"));
            let placeholder_dst = JSON.parse(window.localStorage.getItem("placeholder_dst"));
            $("#add_observable_value_content").append('<span id="add_observable_value"><input class="form-control" type="text" name="add_observable_value_A" id="add_observable_value_A" value="" placeholder="' + placeholder_src[observable_type] + '"> to ' +
                '<input class="form-control" type="text" name="add_observable_value_B" id="add_observable_value_B" value="" placeholder="' + placeholder_dst[observable_type] + '"></span>');
        } else {
            $("#add_observable_modal").modal("hide");
            $("#file_modal").modal("show");
        }
    });

    $("#btn-submit-comment").click(function(e) {
        $("#comment-form").append('<input type="hidden" name="uuids" value="' + current_alert_uuid + '" />');
        $("#comment-form").append('<input type="hidden" name="redirect" value="analysis" />');
        $("#comment-form").submit();
    });

    $("#tag-form").submit(function(e) {
        $("#tag-form").append('<input type="hidden" name="uuids" value="' + current_alert_uuid + '" />');
        $("#tag-form").append('<input type="hidden" name="redirect" value="analysis" />');
    });

    $("#btn-submit-tags").click(function(e) {
        $("#tag-form").submit();
    });

    $("#btn-add-to-event").click(function(e) {
        $("#event-form").append('<input type="hidden" name="alert_uuids" value="' + current_alert_uuid + '" />');
    });

    //$('#btn-stats').click(function(e) {
        //e.preventDefault();
        /*var panel = $.jsPanel({
            position: "center",
            title: "Default Title",
            //content: $(".jsPanel-content"),
            size: { height: 270, width: 430 }
        });
        panel.on("jspanelloaded", function(event, id) {
            graph_alert($(".jsPanel-content")[0]);
        });*/

        //graph_alert($("#visualization")[0]);
    //});

    $('#btn-take-ownership').click(function(e) {
        $('#ownership-form').submit();
    });

    $('#btn-assign-ownership').click(function(e) {
        // add a hidden field to the form and then submit
        $("#assign-ownership-form").append('<input type="hidden" name="alert_uuid" value="' + current_alert_uuid + '" />').submit();
    });

    $("#btn-analyze_alert").click(function(e) {
        $('#analyze-alert-form').submit();
    });

    $("#btn-toggle-prune").click(function(e) {
        $('#toggle-prune-form').submit();
    });

    $("#btn-remediate-alerts").click(function(e) {
        remediate_emails([current_alert_uuid], null);
    });
    

    // pull this out of the disposition form
    current_alert_uuid = $("#alert_uuid").prop("value");

    // event times setup
    document.getElementById("event_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("alert_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("ownership_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("disposition_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("contain_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");
    document.getElementById("remediation_time").value = moment().utc().format("YYYY-MM-DD HH:mm:ss");

    $('input[name="event_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="alert_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="ownership_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="disposition_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="contain_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });
    $('input[name="remediation_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });

    // add observable time setup
    $('input[name="add_observable_time"]').datetimepicker({
        timezone: 0,
        showSecond: false,
        dateFormat: 'yy-mm-dd',
        timeFormat: 'HH:mm:ss'
    });

});

// attachment downloading
var $download_element;

function download_url(url) {
    if ($download_element) {
        $download_element.attr('src', url);
    } else {
        $download_element = $('<iframe>', { id: 'download_element', src: url }).hide().appendTo('body');
    }
}

function graph_alert(container) {
    $.ajax({
        dataType: "json",
        url: '/json',
        data: { alert_uuid: current_alert_uuid },
        success: function(data, textStatus, jqXHR) {
            var nodes = new vis.DataSet(data['nodes']);
            // create an array with edges
            var edges = new vis.DataSet(data['edges']);
            // create a network
            // this must be an actual DOM element
            //var container = $(".jsPanel-content")[0];
            var data = {
                nodes: nodes,
                edges: edges
            };
            var options = {
                nodes: {
                    shape: "dot",
                    size: 10 },
                layout: {
                    /*hierarchical: {
                        enabled: true,
                        sortMethod: 'directed'
                    }*/
                }
            };

            var network = new vis.Network(container, data, options);
            network.stopSimulation();
            network.stabilize();

            // turn off the physics engine once it's stabilized
            network.once("stabilized", function() {
                // don't let it run stabilize again
                network.on("startStabilizing", function() {
                    network.stopSimulation();
                });

                //network.setOptions({
                    //physics: { enabled: false }
                //});
                network.fit();
            });

            network.on("click", function() {
            });

            network.on("resize", function() {
                network.fit();
            });
    
            network.on("selectNode", function(e) {
                for (var i = 0; i < e.nodes.length; i++) {
                    var node = data.nodes.get(e.nodes[i]);
                    if ('details' in node) {
                        data.nodes.update({id: node.id, label: node.details, saved_label: node.label, font: { background: 'white' }});
                    }

                    if ('observable_uuid' in node && 'module_path' in node) {
                        var new_window = window.open("/analysis?observable_uuid=" + node.observable_uuid + "&module_path=" + encodeURIComponent(node.module_path), "");
                        if (new_window) { } else { alert("Unable to open a new window (adblocker?)"); }
                    }
                }
            });

            network.on("deselectNode", function(e) {
                for (var i = 0; i < e.previousSelection.nodes.length; i++) {
                    var node = data.nodes.get(e.previousSelection.nodes[i]);
                    if ('details' in node) {
                        data.nodes.update({id: node.id, label: node.saved_label});
                    }
                }
            });

            $("#btn-fit-to-window").click(function(e) {
                network.fit();
            });
        },
        error: function(jqXHR, textStatus, errorThrown) {
            alert("DOH");
        }
    });
}

function delete_comment(comment_id) {
    if (! confirm("Delete comment?")) 
        return;

    try {
        $("#comment_id").val(comment_id.toString());
    } catch (e) {
        alert(e);
        return;
    }

    $("#delete_comment_form").submit();
}
