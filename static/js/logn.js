document.addEventListener('DOMContentLoaded', function() {
    // Fetch flash messages from the server-side
    var flashMessages = JSON.parse('{{ get_flashed_messages(with_categories=true) | tojson | safe }}');
    
    if (flashMessages.length > 0) {
        flashMessages.forEach(function(message) {
            // Display each flash message as an alert
            alert(message[1]);
        });
    }
});
