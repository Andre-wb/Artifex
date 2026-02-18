// Состояние модальных окон
let currentEditLessonId = null;
let currentEditGradeId = null;
let currentEditSubjectId = null;

// Функции для карусели
function scrollCarousel(offset) {
    document.querySelector('.days-carousel').scrollBy({left: offset, behavior: 'smooth'});
}

// ==================== Функции для уроков ====================
function showAddLessonModal(date) {
    document.getElementById('modalTitle').textContent = 'Добавить урок';
    document.getElementById('lessonId').value = '';
    document.getElementById('lessonDate').value = date;
    document.getElementById('lessonForm').reset();
    document.getElementById('deleteLessonBtn').style.display = 'none';
    document.getElementById('lessonModal').style.display = 'flex';
}

function showEditLessonModal(lessonId) {
    fetch(`/diary/api/lessons/${lessonId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Ошибка загрузки');
            }
            return response.json();
        })
        .then(lesson => {
            document.getElementById('modalTitle').textContent = 'Редактировать урок';
            document.getElementById('lessonId').value = lesson.id;
            document.getElementById('lessonDate').value = lesson.date;
            document.getElementById('subject').value = lesson.subject_id;
            document.getElementById('lessonNumber').value = lesson.lesson_number;
            document.getElementById('startTime').value = lesson.start_time || '';
            document.getElementById('endTime').value = lesson.end_time || '';
            document.getElementById('room').value = lesson.room || '';
            document.getElementById('homework').value = lesson.homework || '';
            document.getElementById('notes').value = lesson.notes || '';
            document.getElementById('deleteLessonBtn').style.display = 'block';
            document.getElementById('lessonModal').style.display = 'flex';
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Ошибка при загрузке урока');
        });
}

function closeModal() {
    document.getElementById('lessonModal').style.display = 'none';
}

// Обработка формы урока
document.addEventListener('DOMContentLoaded', function() {
    const lessonForm = document.getElementById('lessonForm');
    if (lessonForm) {
        lessonForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const lessonId = document.getElementById('lessonId').value;
            const formData = {
                subject_id: parseInt(document.getElementById('subject').value),
                date: document.getElementById('lessonDate').value,
                lesson_number: parseInt(document.getElementById('lessonNumber').value),
                start_time: document.getElementById('startTime').value || null,
                end_time: document.getElementById('endTime').value || null,
                room: document.getElementById('room').value || null,
                homework: document.getElementById('homework').value || null,
                notes: document.getElementById('notes').value || null
            };

            // Проверка обязательных полей
            if (!formData.subject_id) {
                alert('Выберите предмет');
                return;
            }
            if (!formData.date) {
                alert('Укажите дату');
                return;
            }
            if (!formData.lesson_number) {
                alert('Укажите номер урока');
                return;
            }

            const url = lessonId ? `/diary/api/lessons/${lessonId}` : '/diary/api/lessons';
            const method = lessonId ? 'PUT' : 'POST';

            fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            })
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(data => {
                            throw new Error(data.detail || 'Ошибка при сохранении');
                        });
                    }
                    return response.json();
                })
                .then(data => {
                    closeModal();
                    location.reload();
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert(error.message || 'Ошибка при сохранении урока');
                });
        });
    }
});

function deleteLesson() {
    const lessonId = document.getElementById('lessonId').value;
    if (!lessonId) return;

    if (confirm('Вы уверены, что хотите удалить этот урок?')) {
        fetch(`/diary/api/lessons/${lessonId}`, {
            method: 'DELETE'
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Ошибка при удалении');
                }
                return response.json();
            })
            .then(() => {
                closeModal();
                location.reload();
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Ошибка при удалении урока');
            });
    }
}

// ==================== Функции для оценок ====================
function showAddGradeModal(lessonId = null) {
    document.getElementById('gradeModalTitle').textContent = 'Добавить оценку';
    document.getElementById('gradeId').value = '';
    document.getElementById('gradeLessonId').value = lessonId || '';
    document.getElementById('gradeForm').reset();

    // Устанавливаем сегодняшнюю дату по умолчанию
    const today = new Date().toISOString().split('T')[0];
    document.getElementById('gradeDate').value = today;

    document.getElementById('deleteGradeBtn').style.display = 'none';
    document.getElementById('gradeModal').style.display = 'flex';
}

function showEditGradeModal(gradeId) {
    fetch(`/diary/api/grades/${gradeId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Ошибка загрузки');
            }
            return response.json();
        })
        .then(grade => {
            document.getElementById('gradeModalTitle').textContent = 'Редактировать оценку';
            document.getElementById('gradeId').value = grade.id;
            document.getElementById('gradeLessonId').value = grade.lesson_id || '';
            document.getElementById('gradeSubject').value = grade.subject_id;
            document.getElementById('gradeValue').value = grade.value;
            document.getElementById('gradeWeight').value = grade.weight;
            document.getElementById('gradeDate').value = grade.date;
            document.getElementById('gradeDescription').value = grade.description || '';
            document.getElementById('deleteGradeBtn').style.display = 'block';
            document.getElementById('gradeModal').style.display = 'flex';
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Ошибка при загрузке оценки');
        });
}

function closeGradeModal() {
    document.getElementById('gradeModal').style.display = 'none';
}

// Обработка формы оценки
document.addEventListener('DOMContentLoaded', function() {
    const gradeForm = document.getElementById('gradeForm');
    if (gradeForm) {
        gradeForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const gradeId = document.getElementById('gradeId').value;
            const formData = {
                subject_id: parseInt(document.getElementById('gradeSubject').value),
                lesson_id: document.getElementById('gradeLessonId').value ? parseInt(document.getElementById('gradeLessonId').value) : null,
                value: parseInt(document.getElementById('gradeValue').value),
                weight: parseFloat(document.getElementById('gradeWeight').value),
                date: document.getElementById('gradeDate').value,
                description: document.getElementById('gradeDescription').value || null
            };

            // Проверка обязательных полей
            if (!formData.subject_id) {
                alert('Выберите предмет');
                return;
            }
            if (!formData.value) {
                alert('Укажите оценку');
                return;
            }
            if (!formData.date) {
                alert('Укажите дату');
                return;
            }

            const url = gradeId ? `/diary/api/grades/${gradeId}` : '/diary/api/grades';
            const method = gradeId ? 'PUT' : 'POST';

            fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            })
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(data => {
                            throw new Error(data.detail || 'Ошибка при сохранении');
                        });
                    }
                    return response.json();
                })
                .then(data => {
                    closeGradeModal();
                    location.reload();
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert(error.message || 'Ошибка при сохранении оценки');
                });
        });
    }
});

function deleteGrade() {
    const gradeId = document.getElementById('gradeId').value;
    if (!gradeId) return;

    if (confirm('Вы уверены, что хотите удалить эту оценку?')) {
        fetch(`/diary/api/grades/${gradeId}`, {
            method: 'DELETE'
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Ошибка при удалении');
                }
                return response.json();
            })
            .then(() => {
                closeGradeModal();
                location.reload();
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Ошибка при удалении оценки');
            });
    }
}

// ==================== Функции для предметов ====================
function showAddSubjectModal() {
    document.getElementById('subjectModalTitle').textContent = 'Добавить предмет';
    document.getElementById('subjectId').value = '';
    document.getElementById('subjectForm').reset();
    document.getElementById('deleteSubjectBtn').style.display = 'none';
    document.getElementById('subjectModal').style.display = 'flex';
}

function showEditSubjectModal(subjectId) {
    fetch(`/diary/api/subjects/${subjectId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Ошибка загрузки');
            }
            return response.json();
        })
        .then(subject => {
            document.getElementById('subjectModalTitle').textContent = 'Редактировать предмет';
            document.getElementById('subjectId').value = subject.id;
            document.getElementById('subjectName').value = subject.name;
            document.getElementById('subjectDescription').value = subject.description || '';
            document.getElementById('deleteSubjectBtn').style.display = 'block';
            document.getElementById('subjectModal').style.display = 'flex';
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Ошибка при загрузке предмета');
        });
}

function closeSubjectModal() {
    document.getElementById('subjectModal').style.display = 'none';
}

// Обработка формы предмета
document.addEventListener('DOMContentLoaded', function() {
    const subjectForm = document.getElementById('subjectForm');
    if (subjectForm) {
        subjectForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const subjectId = document.getElementById('subjectId').value;
            const formData = {
                name: document.getElementById('subjectName').value,
                description: document.getElementById('subjectDescription').value || null
            };

            if (!formData.name) {
                alert('Введите название предмета');
                return;
            }

            const url = subjectId ? `/diary/api/subjects/${subjectId}` : '/diary/api/subjects';
            const method = subjectId ? 'PUT' : 'POST';

            fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            })
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(data => {
                            throw new Error(data.detail || 'Ошибка при сохранении');
                        });
                    }
                    return response.json();
                })
                .then(data => {
                    closeSubjectModal();
                    location.reload();
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert(error.message || 'Ошибка при сохранении предмета');
                });
        });
    }
});

function deleteSubject() {
    const subjectId = document.getElementById('subjectId').value;
    if (!subjectId) return;

    if (confirm('Вы уверены, что хотите удалить этот предмет? Убедитесь, что к нему не привязаны уроки.')) {
        fetch(`/diary/api/subjects/${subjectId}`, {
            method: 'DELETE'
        })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.detail || 'Ошибка при удалении');
                    });
                }
                return response.json();
            })
            .then(() => {
                closeSubjectModal();
                location.reload();
            })
            .catch(error => {
                console.error('Error:', error);
                alert(error.message || 'Ошибка при удалении предмета');
            });
    }
}

// ==================== Функция генерации уроков ====================
function generateLessonsFromTemplate() {
    if (!confirm('Создать уроки на 2 недели вперед из шаблона? Существующие уроки будут обновлены.')) {
        return;
    }

    fetch('/diary/api/generate-lessons?weeks_ahead=2', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Ошибка при создании уроков');
            }
            return response.json();
        })
        .then(data => {
            alert('Уроки успешно созданы!');
            location.reload();
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Ошибка при создании уроков');
        });
}

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
    // Добавляем кнопку для создания предметов на страницу, если её нет
    const diaryHeader = document.querySelector('.diary-header');
    if (diaryHeader && !document.getElementById('addSubjectBtn')) {
        const subjectBtn = document.createElement('button');
        subjectBtn.id = 'addSubjectBtn';
        subjectBtn.className = 'btn btn-primary';
        subjectBtn.style.marginLeft = '10px';
        subjectBtn.innerHTML = '➕ Управление предметами';
        subjectBtn.onclick = showAddSubjectModal;
        diaryHeader.appendChild(subjectBtn);
    }

    // Добавляем модальное окно для предметов, если его нет
    if (!document.getElementById('subjectModal')) {
        const modalHTML = `
            <div id="subjectModal" class="modal">
                <div class="modal-content">
                    <h2 id="subjectModalTitle">Добавить предмет</h2>
                    <form id="subjectForm">
                        <input type="hidden" id="subjectId" name="subjectId">

                        <div class="form-group">
                            <label for="subjectName">Название предмета *</label>
                            <input type="text" id="subjectName" name="name" required maxlength="50">
                        </div>

                        <div class="form-group">
                            <label for="subjectDescription">Описание (необязательно)</label>
                            <textarea id="subjectDescription" name="description" rows="2" style="resize: none"></textarea>
                        </div>

                        <div class="modal-buttons">
                            <button type="submit" class="btn btn-primary">Сохранить</button>
                            <button type="button" class="btn btn-secondary" onclick="closeSubjectModal()">Отмена</button>
                            <button type="button" class="btn btn-danger" id="deleteSubjectBtn" style="display: none;" onclick="deleteSubject()">Удалить</button>
                        </div>
                    </form>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHTML);
    }
});