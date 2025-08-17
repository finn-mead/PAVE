function handleImageUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const preview = document.getElementById('image-preview');
    const prompt = document.getElementById('upload-prompt');
    const removeBtn = document.getElementById('remove-btn');
    const uploadArea = document.querySelector('.upload-area');
    
    const url = URL.createObjectURL(file);
    preview.src = url;
    preview.style.display = 'block';
    prompt.style.display = 'none';
    removeBtn.style.display = 'inline-block';
    uploadArea.classList.add('has-image');
}

function removeImage(event) {
    event.stopPropagation();
    
    const preview = document.getElementById('image-preview');
    const prompt = document.getElementById('upload-prompt');
    const removeBtn = document.getElementById('remove-btn');
    const uploadArea = document.querySelector('.upload-area');
    const fileInput = document.getElementById('photo-input');
    
    if (preview.src) {
        URL.revokeObjectURL(preview.src);
    }
    
    preview.src = '';
    preview.style.display = 'none';
    prompt.style.display = 'block';
    removeBtn.style.display = 'none';
    uploadArea.classList.remove('has-image');
    fileInput.value = '';
}

document.addEventListener('DOMContentLoaded', function() {
    const uploadArea = document.querySelector('.upload-area');
    const fileInput = document.getElementById('photo-input');
    const removeBtn = document.getElementById('remove-btn');
    
    uploadArea.addEventListener('click', function() {
        fileInput.click();
    });
    
    fileInput.addEventListener('change', handleImageUpload);
    removeBtn.addEventListener('click', removeImage);
});