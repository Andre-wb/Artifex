(function() {
    const teacherCheckbox = document.querySelector('input[name="is_teacher"]');
    const gradeInput = document.getElementById('grade');

    if (teacherCheckbox && gradeInput) {
        teacherCheckbox.addEventListener('change', function(e) {
            gradeInput.required = !e.target.checked;
        });
    }

    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', function(event) {
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm').value;

            if (password !== confirm) {
                event.preventDefault();
                alert('Пароли не совпадают! Проверьте правильность ввода.');
                document.getElementById('confirm').focus();
                return false;
            }

            if (password.length < 12) {
                event.preventDefault();
                alert('Пароль должен быть не менее 12 символов!');
                document.getElementById('password').focus();
                return false;
            }

            const username = document.getElementById('username').value;
            const usernamePattern = /^[a-zA-Z0-9_]{3,30}$/;
            if (!usernamePattern.test(username)) {
                event.preventDefault();
                alert('Имя пользователя должно содержать только буквы, цифры и подчеркивания, от 3 до 30 символов');
                document.getElementById('username').focus();
                return false;
            }

            const school = document.getElementById('school').value;
            if (!school) {
                event.preventDefault();
                alert('Пожалуйста, укажите школу');
                document.getElementById('school').focus();
                return false;
            }

            const isTeacher = teacherCheckbox ? teacherCheckbox.checked : false;
            const grade = gradeInput ? gradeInput.value : '';
            if (!isTeacher && !grade) {
                event.preventDefault();
                alert('Для ученика класс обязателен');
                if (gradeInput) gradeInput.focus();
                return false;
            }

            return true;
        });
    }

    const inputs = document.querySelectorAll('.input');
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
        });
        input.addEventListener('blur', function() {
            this.parentElement.classList.remove('focused');
        });
    });
})();