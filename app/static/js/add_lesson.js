// Состояние модальных окон
let currentDeleteId = null;
let isTeacher = false;

// Проверяем роль при загрузке
document.addEventListener('DOMContentLoaded', function() {
    isTeacher = document.querySelector('.teacher-only') !== null;
});

// Функции для основного модального окна
function showAddTemplateModal(dayIndex) {
    if (!isTeacher) {
        alert('Только учителя могут редактировать расписание');
        return;
    }
    document.getElementById('templateId').value = '';
    document.getElementById('templateDay').value = dayIndex;
    document.getElementById('modalTitle').textContent = 'Добавить урок в шаблон';
    document.getElementById('templateForm').reset();
    document.getElementById('templateModal').style.display = 'flex';
}

function editTemplate(id) {
    if (!isTeacher) {
        alert('Только учителя могут редактировать расписание');
        return;
    }
    // Используем существующий API эндпоинт для получения урока
    fetch(`/diary/api/lessons/${id}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Ошибка загрузки');
            }
            return response.json();
        })
        .then(data => {
            document.getElementById('templateId').value = data.id;
            document.getElementById('templateDay').value = new Date(data.date).getDay() || 0;
            document.getElementById('templateSubject').value = data.subject_id;
            document.getElementById('templateLessonNumber').value = data.lesson_number;
            document.getElementById('templateStartTime').value = data.start_time || '';
            document.getElementById('templateEndTime').value = data.end_time || '';
            document.getElementById('templateRoom').value = data.room || '';
            document.getElementById('modalTitle').textContent = 'Редактировать урок';
            document.getElementById('templateModal').style.display = 'flex';
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Ошибка при загрузке данных урока', 'error');
        });
}

function closeModal() {
    document.getElementById('templateModal').style.display = 'none';
}

// Функции для модального окна нового предмета
function showNewSubjectModal() {
    if (!isTeacher) {
        alert('Только учителя могут создавать предметы');
        return;
    }
    document.getElementById('newSubjectForm').reset();
    document.getElementById('newSubjectModal').style.display = 'flex';
}

function closeNewSubjectModal() {
    document.getElementById('newSubjectModal').style.display = 'none';
}

// Создание нового предмета
function createNewSubject(event) {
    event.preventDefault();

    if (!isTeacher) {
        alert('Только учителя могут создавать предметы');
        return;
    }

    const formData = {
        name: document.getElementById('newSubjectName').value,
        description: document.getElementById('newSubjectDescription').value
    };

    // Используем существующий API эндпоинт для создания предмета
    fetch('/diary/api/subjects', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData)
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Ошибка создания');
            }
            return response.json();
        })
        .then(data => {
            // Добавляем новый предмет в выпадающий список
            const select = document.getElementById('templateSubject');
            const option = document.createElement('option');
            option.value = data.id;
            option.textContent = data.name;
            select.appendChild(option);

            // Выбираем новый предмет
            select.value = data.id;

            // Закрываем модальное окно
            closeNewSubjectModal();

            // Показываем уведомление
            showNotification('Предмет успешно создан', 'success');
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Ошибка при создании предмета', 'error');
        });
}

// Функции для подтверждения удаления
function deleteTemplate(id) {
    if (!isTeacher) {
        alert('Только учителя могут удалять уроки');
        return;
    }
    currentDeleteId = id;
    document.getElementById('confirmMessage').textContent = 'Вы уверены, что хотите удалить этот урок из шаблона?';
    document.getElementById('confirmModal').style.display = 'flex';
}

function closeConfirmModal() {
    document.getElementById('confirmModal').style.display = 'none';
    currentDeleteId = null;
}

function confirmDelete() {
    if (!isTeacher) return;

    if (currentDeleteId) {
        // Используем существующий API эндпоинт для удаления урока
        fetch(`/diary/api/lessons/${currentDeleteId}`, {
            method: 'DELETE'
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Ошибка удаления');
                }
                // Удаляем элемент из DOM
                const element = document.querySelector(`[data-template-id="${currentDeleteId}"]`);
                if (element) {
                    element.remove();
                }
                closeConfirmModal();
                showNotification('Урок успешно удален', 'success');
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('Ошибка при удалении', 'error');
                closeConfirmModal();
            });
    }
}

// Функция генерации уроков (доступна всем)
function generateLessons() {
    if (confirm('Создать уроки на 2 недели вперед из текущего шаблона?')) {
        // Используем существующий API эндпоинт для генерации
        fetch('/diary/api/generate-lessons?weeks_ahead=2', {
            method: 'POST'
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Ошибка генерации');
                }
                return response.json();
            })
            .then(data => {
                showNotification('Уроки успешно созданы!', 'success');
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('Ошибка при создании уроков', 'error');
            });
    }
}

// Обработка отправки формы шаблона
if (document.getElementById('templateForm')) {
    document.getElementById('templateForm').addEventListener('submit', function(e) {
        e.preventDefault();

        if (!isTeacher) {
            alert('Только учителя могут изменять расписание');
            return;
        }

        const formData = {
            day_of_week: parseInt(document.getElementById('templateDay').value),
            subject_id: parseInt(document.getElementById('templateSubject').value),
            lesson_number: parseInt(document.getElementById('templateLessonNumber').value),
            start_time: document.getElementById('templateStartTime').value || null,
            end_time: document.getElementById('templateEndTime').value || null,
            room: document.getElementById('templateRoom').value || null
        };

        const id = document.getElementById('templateId').value;

        // Используем существующий API эндпоинт для создания/обновления шаблона
        fetch('/diary/api/timetable-template', {
            method: 'POST',  // Эндпоинт работает и как create, и как update
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Ошибка сохранения');
                }
                return response.json();
            })
            .then(data => {
                showNotification(id ? 'Урок обновлен' : 'Урок добавлен', 'success');
                setTimeout(() => location.reload(), 1000); // Перезагружаем через секунду
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('Ошибка при сохранении', 'error');
            });
    });
}

// Функция показа уведомлений
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        background: ${type === 'success' ? '#4ade80' : '#fb242b'};
        color: white;
        border-radius: 12px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        z-index: 2000;
        animation: slideIn 0.3s ease;
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Закрытие модальных окон по клику вне их
window.onclick = function(event) {
    const modals = ['templateModal', 'newSubjectModal', 'confirmModal'];
    modals.forEach(modalId => {
        const modal = document.getElementById(modalId);
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}

// Добавляем стили для анимаций, если их нет в CSS
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);