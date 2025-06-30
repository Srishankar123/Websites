function deleteNote(noteId) {
    fetch('/delete-note', {
        method: 'POST',
        body: JSON.stringify({ note: noteId })  // key matches what Flask expects
    }).then((_res) => {
        window.location.href = "/";
    });
}
