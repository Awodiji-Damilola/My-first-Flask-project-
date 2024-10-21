    var phone_input = document.getElementById('phone');
    var fancy_phone_input = document.getElementById('_phone');

    // Initialize intl-tel-input on the visible phone field
    var fancy_phone_iti = window.intlTelInput(fancy_phone_input, {
        separateDialCode: true,
        utilsScript: "https://cdnjs.cloudflare.com/ajax/libs/intl-tel-input/16.0.4/js/utils.js",
    });

    // Set initial value (if any) in the visible field
    fancy_phone_iti.setNumber(phone_input.value);

    // When the user leaves the input field, set the hidden input to the full international number
    fancy_phone_input.addEventListener('blur', function() {
        phone_input.value = fancy_phone_iti.getNumber();
    });

