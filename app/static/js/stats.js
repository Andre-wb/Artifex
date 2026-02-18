let subjects = [];
let students = [];
let currentFilters = {
    subject_id: '',
    date_from: '',
    date_to: ''
};
let currentEditGradeId = null;
let isTeacher = false;

// Проверяем роль пользователя
document.addEventListener('DOMContentLoaded', function() {
    // Проверяем наличие элементов teacher-only
    isTeacher = document.querySelector('.teacher-only') !== null;

    fetch('/diary/api/subjects')
        .then(response => response.json())
        .then(data => {
            subjects = data;
            populateSubjectFilter();
            loadAverages();
            loadGrades();
        });

    if (isTeacher) {
        loadStudents();
    }
});

function loadStudents() {
    fetch('/teacher/students')
        .then(response => response.json())
        .then(data => {
            students = data;
            const studentSelect = document.getElementById('gradeStudent');
            if (studentSelect) {
                studentSelect.innerHTML = '<option value="">Выберите ученика</option>';
                students.forEach(student => {
                    studentSelect.innerHTML += `<option value="${student.id}">${student.username} (${student.grade || 'Класс не указан'})</option>`;
                });
            }
        })
        .catch(error => {
            console.error('Error loading students:', error);
        });
}

function populateSubjectFilter() {
    const select = document.getElementById('subjectFilter');
    select.innerHTML = '<option value="">Все предметы</option>';
    subjects.forEach(subject => {
        select.innerHTML += `<option value="${subject.id}">${subject.name}</option>`;
    });

    if (isTeacher) {
        const gradeSubject = document.getElementById('gradeSubject');
        if (gradeSubject) {
            gradeSubject.innerHTML = '<option value="">Выберите предмет</option>';
            subjects.forEach(subject => {
                gradeSubject.innerHTML += `<option value="${subject.id}">${subject.name}</option>`;
            });
        }
    }
}

function applyFilters() {
    currentFilters = {
        subject_id: document.getElementById('subjectFilter').value,
        date_from: document.getElementById('dateFrom').value,
        date_to: document.getElementById('dateTo').value
    };
    loadGrades();
}

function loadAverages() {
    fetch('/diary/api/stats/averages')
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('averagesContainer');
            container.innerHTML = '';

            data.forEach(stat => {
                const gradeClass = getGradeClass(stat.average);
                container.innerHTML += `
                    <div class="subject-card" style="border-top-color: ${stat.color || '#667eea'}">
                        <div class="subject-header">
                            <span class="subject-name">${stat.subject_name}</span>
                            <span class="subject-average ${gradeClass}">${stat.average.toFixed(2)}</span>
                        </div>
                        <div class="grades-count">Всего оценок: ${stat.grades_count}</div>
                    </div>
                `;
            });
        });
}

function loadGrades() {
    let url = '/diary/api/grades?';
    if (currentFilters.subject_id) url += `&subject_id=${currentFilters.subject_id}`;
    if (currentFilters.date_from) url += `&date_from=${currentFilters.date_from}`;
    if (currentFilters.date_to) url += `&date_to=${currentFilters.date_to}`;

    fetch(url)
        .then(response => response.json())
        .then(data => {
            const tbody = document.querySelector('#gradesTable tbody');
            tbody.innerHTML = '';

            data.forEach(grade => {
                const gradeClass = `grade-${grade.value}`;
                let row = `
                    <tr>
                        <td>${formatDate(grade.date)}</td>
                        <td>${grade.subject.name}</td>
                        <td><span class="grade-badge ${gradeClass}">${grade.value}</span></td>
                        <td>${grade.weight}</td>
                        <td>${grade.description || '-'}</td>
                        <td>${grade.lesson ? grade.lesson.subject.name + ' (' + grade.lesson.date + ')' : '-'}</td>
                `;

                // Добавляем колонку действий только для учителей
                if (isTeacher) {
                    row += `
                        <td class="teacher-only">
                            <button onclick="showEditGradeModal(${grade.id})" style="margin-right:5px;">✏️</button>
                            <button onclick="deleteGrade(${grade.id})">🗑️</button>
                        </td>
                    `;
                }

                row += '</tr>';
                tbody.innerHTML += row;
            });
        });
}

function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleDateString('ru-RU');
}

function getGradeClass(average) {
    if (average >= 4.5) return 'grade-5';
    if (average >= 3.5) return 'grade-4';
    if (average >= 2.5) return 'grade-3';
    return 'grade-2';
}

function showAddGradeModal() {
    if (!isTeacher) {
        alert('Только учителя могут добавлять оценки');
        return;
    }
    document.getElementById('gradeModalTitle').textContent = 'Добавить оценку';
    document.getElementById('gradeId').value = '';
    document.getElementById('gradeLessonId').value = '';
    document.getElementById('gradeForm').reset();
    document.getElementById('gradeDate').value = new Date().toISOString().split('T')[0];
    document.getElementById('deleteGradeBtn').style.display = 'none';
    document.getElementById('gradeModal').style.display = 'flex';
}

function showEditGradeModal(gradeId) {
    if (!isTeacher) {
        alert('Только учителя могут редактировать оценки');
        return;
    }
    fetch(`/diary/api/grades/${gradeId}`)
        .then(response => response.json())
        .then(grade => {
            document.getElementById('gradeModalTitle').textContent = 'Редактировать оценку';
            document.getElementById('gradeId').value = grade.id;
            document.getElementById('gradeLessonId').value = grade.lesson_id || '';
            document.getElementById('gradeSubject').value = grade.subject_id;
            document.getElementById('gradeValue').value = grade.value;
            document.getElementById('gradeWeight').value = grade.weight;
            document.getElementById('gradeDate').value = grade.date;
            document.getElementById('gradeDescription').value = grade.description || '';
            if (document.getElementById('gradeStudent')) {
                document.getElementById('gradeStudent').value = grade.user_id;
            }
            document.getElementById('deleteGradeBtn').style.display = 'block';
            document.getElementById('gradeModal').style.display = 'flex';
        });
}

function closeGradeModal() {
    document.getElementById('gradeModal').style.display = 'none';
}

if (document.getElementById('gradeForm')) {
    document.getElementById('gradeForm').addEventListener('submit', function(e) {
        e.preventDefault();

        const gradeId = document.getElementById('gradeId').value;
        const formData = {
            subject_id: parseInt(document.getElementById('gradeSubject').value),
            lesson_id: document.getElementById('gradeLessonId').value || null,
            value: parseInt(document.getElementById('gradeValue').value),
            weight: parseFloat(document.getElementById('gradeWeight').value),
            date: document.getElementById('gradeDate').value,
            description: document.getElementById('gradeDescription').value || null
        };

        // Добавляем user_id для учителя
        if (isTeacher && document.getElementById('gradeStudent') && document.getElementById('gradeStudent').value) {
            formData.user_id = parseInt(document.getElementById('gradeStudent').value);
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
                if (response.ok) {
                    closeGradeModal();
                    loadGrades();
                    loadAverages();
                } else {
                    response.json().then(data => {
                        alert('Ошибка при сохранении оценки: ' + (data.detail || 'Неизвестная ошибка'));
                    });
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Ошибка при сохранении оценки');
            });
    });
}

function deleteGrade() {
    if (!isTeacher) {
        alert('Только учителя могут удалять оценки');
        return;
    }
    const gradeId = document.getElementById('gradeId').value;
    if (!gradeId) return;

    if (confirm('Вы уверены, что хотите удалить эту оценку?')) {
        fetch(`/diary/api/grades/${gradeId}`, {
            method: 'DELETE'
        })
            .then(response => {
                if (response.ok) {
                    closeGradeModal();
                    loadGrades();
                    loadAverages();
                } else {
                    alert('Ошибка при удалении оценки');
                }
            });
    }
}