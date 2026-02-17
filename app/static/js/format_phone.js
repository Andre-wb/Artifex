function formatPhoneNumber(inputElement) {
    if (!inputElement) return;
    inputElement.addEventListener('input', function(e) {
        let value = e.target.value.replace(/\D/g, '');
        if (value.startsWith('7') || value.startsWith('8')) {
            let formatted = '+7';
            if (value.length > 1) {
                formatted += ' ' + value.substring(1, 4);
            }
            if (value.length > 4) {
                formatted += ' ' + value.substring(4, 7);
            }
            if (value.length > 7) {
                formatted += '-' + value.substring(7, 9);
            }
            if (value.length > 9) {
                formatted += '-' + value.substring(9, 11);
            }
            e.target.value = formatted;
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    const phoneInput = document.getElementById('phone');
    if (phoneInput) {
        formatPhoneNumber(phoneInput);
    }
});