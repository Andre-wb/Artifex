let currentEditTemplateId = null;

function showAddTemplateModal(day) {
    document.getElementById('modalTitle').textContent = 'Добавить урок в шаблон';
    document.getElementById('templateId').value = '';
    document.getElementById('templateDay').value = day;
    document.getElementById('templateForm').reset();
    document.getElementById('templateModal').style.display = 'flex';
}

function editTemplate(templateId) {
    fetch(`/diary/api/timetable-template/${templateId}`)
        .then(response => response.json())
        .then(template => {
            document.getElementById('modalTitle').textContent = 'Редактировать урок в шаблоне';
            document.getElementById('templateId').value = template.id;
            document.getElementById('templateDay').value = template.day_of_week;
            document.getElementById('templateSubject').value = template.subject_id;
            document.getElementById('templateLessonNumber').value = template.lesson_number;
            document.getElementById('templateStartTime').value = template.start_time || '';
            document.getElementById('templateEndTime').value = template.end_time || '';
            document.getElementById('templateRoom').value = template.room || '';
            document.getElementById('templateModal').style.display = 'flex';
        });
}

function closeModal() {
    document.getElementById('templateModal').style.display = 'none';
}

document.getElementById('templateForm').addEventListener('submit', function(e) {
    e.preventDefault();

    const templateId = document.getElementById('templateId').value;
    const formData = {
        day_of_week: parseInt(document.getElementById('templateDay').value),
        lesson_number: parseInt(document.getElementById('templateLessonNumber').value),
        subject_id: parseInt(document.getElementById('templateSubject').value),
        start_time: document.getElementById('templateStartTime').value || null,
        end_time: document.getElementById('templateEndTime').value || null,
        room: document.getElementById('templateRoom').value || null
    };

    const url = templateId ? `/diary/api/timetable-template/${templateId}` : '/diary/api/timetable-template';
    const method = templateId ? 'PUT' : 'POST';

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
                alert('Ошибка при сохранении');
            }
        });
});

function deleteTemplate(templateId) {
    if (confirm('Удалить этот урок из шаблона?')) {
        fetch(`/diary/api/timetable-template/${templateId}`, {
            method: 'DELETE'
        })
            .then(response => {
                if (response.ok) {
                    location.reload();
                } else {
                    alert('Ошибка при удалении');
                }
            });
    }
}

function generateLessons() {
    if (confirm('Создать уроки на 2 недели вперед из шаблона?')) {
        fetch('/diary/api/generate-lessons', {
            method: 'POST'
        })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                window.location.href = '/diary';
            });
    }
}