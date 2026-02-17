let currentEditLessonId = null;
let currentEditGradeId = null;

function scrollCarousel(offset) {
    document.querySelector('.days-carousel').scrollBy({left: offset, behavior: 'smooth'});
}

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
        .then(response => response.json())
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
        });
}

function closeModal() {
    document.getElementById('lessonModal').style.display = 'none';
}

document.getElementById('lessonForm').addEventListener('submit', function(e) {
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
            if (response.ok) {
                closeModal();
                location.reload();
            } else {
                alert('Ошибка при сохранении урока');
            }
        });
});

function deleteLesson() {
    const lessonId = document.getElementById('lessonId').value;
    if (!lessonId) return;

    if (confirm('Вы уверены, что хотите удалить этот урок?')) {
        fetch(`/diary/api/lessons/${lessonId}`, {
            method: 'DELETE'
        })
            .then(response => {
                if (response.ok) {
                    closeModal();
                    location.reload();
                } else {
                    alert('Ошибка при удалении урока');
                }
            });
    }
}

function showAddGradeModal(lessonId = null) {
    document.getElementById('gradeModalTitle').textContent = 'Добавить оценку';
    document.getElementById('gradeId').value = '';
    document.getElementById('gradeLessonId').value = lessonId || '';
    document.getElementById('gradeForm').reset();
    document.getElementById('gradeDate').value = new Date().toISOString().split('T')[0];
    document.getElementById('deleteGradeBtn').style.display = 'none';
    document.getElementById('gradeModal').style.display = 'flex';
}

function showEditGradeModal(gradeId) {
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
            document.getElementById('deleteGradeBtn').style.display = 'block';
            document.getElementById('gradeModal').style.display = 'flex';
        });
}

function closeGradeModal() {
    document.getElementById('gradeModal').style.display = 'none';
}

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
                location.reload();
            } else {
                alert('Ошибка при сохранении оценки');
            }
        });
});

function deleteGrade() {
    const gradeId = document.getElementById('gradeId').value;
    if (!gradeId) return;

    if (confirm('Вы уверены, что хотите удалить эту оценку?')) {
        fetch(`/diary/api/grades/${gradeId}`, {
            method: 'DELETE'
        })
            .then(response => {
                if (response.ok) {
                    closeGradeModal();
                    location.reload();
                } else {
                    alert('Ошибка при удалении оценки');
                }
            });
    }
}