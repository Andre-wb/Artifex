/**
 * Проверка сложности пароля и отображение индикатора.
 * Используется на странице регистрации.
 */
function checkPasswordStrength(password) {
    const strengthDiv = document.getElementById('password-strength');
    const fill = document.getElementById('strength-fill');
    const text = document.getElementById('strength-text');

    if (!password) {
        strengthDiv.style.display = 'none';
        return;
    }

    strengthDiv.style.display = 'block';

    let score = 0;

    if (password.length >= 16) score += 40;
    else if (password.length >= 12) score += 30;
    else if (password.length >= 8) score += 20;
    else if (password.length >= 6) score += 10;

    if (/[A-ZА-Я]/.test(password)) score += 15;
    if (/[a-zа-я]/.test(password)) score += 15;
    if (/\d/.test(password)) score += 15;
    if (/[!@#$%^&*(),.?":{}|<>\[\]\\/+=_\-]/.test(password)) score += 15;

    if (/(.)\1{3,}/.test(password)) score -= 20; // повторяющиеся символы
    if (/(123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) score -= 20; // последовательности
    if (/password|123456|qwerty|admin|letmein|welcome|monkey|dragon|trustno1|sunshine|master|hello|freedom|whatever|qazwsx|password1|superman/i.test(password)) score = 0;

    score = Math.max(0, Math.min(score, 100));

    fill.style.width = score + '%';

    if (score >= 80) {
        fill.style.backgroundColor = '#27ae60';
        text.textContent = 'Отличный пароль!';
        text.style.color = '#27ae60';
    } else if (score >= 60) {
        fill.style.backgroundColor = '#2ecc71';
        text.textContent = 'Хороший пароль';
        text.style.color = '#2ecc71';
    } else if (score >= 40) {
        fill.style.backgroundColor = '#f39c12';
        text.textContent = 'Средний пароль';
        text.style.color = '#f39c12';
    } else if (score >= 20) {
        fill.style.backgroundColor = '#e67e22';
        text.textContent = 'Слабый пароль';
        text.style.color = '#e67e22';
    } else {
        fill.style.backgroundColor = '#e74c3c';
        text.textContent = 'Очень слабый пароль';
        text.style.color = '#e74c3c';
    }
}