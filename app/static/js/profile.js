// Загрузка достижений пользователя
document.addEventListener('DOMContentLoaded', function() {
    // Загрузка достижений
    fetch('/gamification/achievements')
        .then(response => response.json())
        .then(achievements => {
            const container = document.getElementById('achievementsContainer');
            const earnedAchievements = achievements.filter(a => a.earned);

            if (earnedAchievements.length > 0) {
                container.innerHTML = earnedAchievements.map(ach => `
                        <div class="achievement-card">
                            <div class="achievement-icon">🏆</div>
                            <div class="achievement-name">${ach.name}</div>
                            <div class="achievement-date">${new Date(ach.earned_at).toLocaleDateString('ru-RU')}</div>
                        </div>
                    `).join('');
            } else {
                container.innerHTML = `
                        <div class="empty-state" style="grid-column: 1/-1;">
                            Пока нет достижений. Выполняйте задания и получайте награды!
                        </div>
                    `;
            }
        })
        .catch(error => {
            console.error('Error loading achievements:', error);
            document.getElementById('achievementsContainer').innerHTML = `
                    <div class="empty-state" style="grid-column: 1/-1;">
                        Не удалось загрузить достижения
                    </div>
                `;
        });

    // Загрузка предупреждений о нагрузке
    fetch('/diary/api/load-analysis')
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('warningsContainer');

            if (data.warnings && data.warnings.length > 0) {
                container.innerHTML = data.warnings.map(warning => `
                        <div class="warning-item">
                            <div class="warning-title">⚠️ ${warning.date}</div>
                            <div class="warning-text">${warning.message}</div>
                            <div class="warning-text" style="margin-top: var(--spacing-xs); color: var(--text-primary);">
                                💡 ${warning.advice}
                            </div>
                        </div>
                    `).join('');
            } else {
                container.innerHTML = `
                        <div class="empty-state">
                            ✅ Отличная нагрузка! Нет сложных дней на этой неделе.
                        </div>
                    `;
            }
        })
        .catch(error => {
            console.error('Error loading warnings:', error);
        });
});