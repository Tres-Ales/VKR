$(function () {
        $("#toKnow").click(function () {
            if ($(this).is(":checked")) {
                $("#div_interests").show();
            } else {
                $("#div_interests").hide();
            }
        });
    });



function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
};

async function throwEvent() {
    var ExtID = "kggdakehmneaofldholladdcnidfhlmh";
    chrome.runtime.sendMessage(ExtID, {openUrlInEditor: "hello"},
        function(response) {});
    await sleep(500);
    document.getElementById("form_id").submit();
};