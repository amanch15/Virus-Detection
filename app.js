class DocumentScanner {
  constructor() {
    this.fileInput = document.getElementById('fileInput');
    this.dropZone = document.getElementById('dropZone');
    this.uploadLabel = document.getElementById('uploadLabel');
    this.filenameDisplay = document.getElementById('filenameDisplay');
    this.fileDetails = document.getElementById('fileDetails');
    this.scannerStatus = document.getElementById('scannerStatus');
    this.progressBar = document.getElementById('progressBar');
    this.progressPercent = document.getElementById('progressPercent');
    this.timeRemaining = document.getElementById('timeRemaining');
    this.scanResult = document.getElementById('scanResult');
    this.scanMeta = document.getElementById('scanMeta');
    
    this.scanDuration = 5000; // 5 seconds scan time
    this.scanInterval = null;
    
    this.initEventListeners();
  }
  
  initEventListeners() {
    // File input change
    this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
    
    // Upload button click
    this.uploadLabel.addEventListener('click', () => this.fileInput.click());
    this.uploadLabel.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        this.fileInput.click();
      }
    });
    
    // Drag and drop events
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      this.dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
      });
    });
    
    ['dragenter', 'dragover'].forEach(eventName => {
      this.dropZone.addEventListener(eventName, () => {
        this.dropZone.classList.add('active');
      });
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
      this.dropZone.addEventListener(eventName, () => {
        this.dropZone.classList.remove('active');
      });
    });
    
    this.dropZone.addEventListener('drop', (e) => {
      this.fileInput.files = e.dataTransfer.files;
      this.handleFileSelect(e);
    });
  }
  
  handleFileSelect(e) {
    this.resetUI();
    
    if (e.target.files.length === 0) return;
    const file = e.target.files[0];
    
    // Validate file type
    const validTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'text/plain',
      'application/rtf',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    ];
    
    if (!validTypes.includes(file.type)) {
      this.showError('Unsupported file type. Please upload a document file.');
      return;
    }
    
    // Update UI with file info
    this.displayFileInfo(file);
    this.simulateScan(file);
  }
  
  displayFileInfo(file) {
    // Display filename
    let name = file.name;
    if (name.length > 40) {
      const extIndex = name.lastIndexOf('.');
      const ext = extIndex !== -1 ? name.substring(extIndex) : '';
      name = name.substring(0, 20) + '...' + ext;
    }
    this.filenameDisplay.textContent = name;
    
    // Display file details
    const fileSize = this.formatFileSize(file.size);
    const fileType = this.getFileType(file.type);
    
    this.fileDetails.innerHTML = `
      <span><i class="fas fa-file-alt"></i> ${fileType}</span>
      <span><i class="fas fa-database"></i> ${fileSize}</span>
      <span><i class="fas fa-calendar-alt"></i> ${new Date().toLocaleDateString()}</span>
    `;
    
    // Update upload button
    this.uploadLabel.querySelector('.btn-text').textContent = 'Scan Document';
    this.uploadLabel.setAttribute('aria-pressed', 'true');
  }
  
  simulateScan(file) {
    this.scannerStatus.textContent = `Analyzing "${file.name}"...`;
    this.scannerStatus.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Analyzing "${file.name}"...`;
    
    let progress = 0;
    const intervalTime = 100;
    const increment = (intervalTime / this.scanDuration) * 100;
    const startTime = Date.now();
    
    this.scanInterval = setInterval(() => {
      progress += increment;
      const elapsed = Date.now() - startTime;
      const remaining = Math.max(0, this.scanDuration - elapsed);
      
      if (progress >= 100) {
        progress = 100;
        clearInterval(this.scanInterval);
        this.onScanComplete(file);
      }
      
      this.updateProgress(progress, remaining);
    }, intervalTime);
  }
  
  updateProgress(progress, remaining) {
    this.progressBar.style.width = progress + '%';
    this.progressPercent.textContent = Math.round(progress) + '%';
    this.timeRemaining.textContent = `~${Math.ceil(remaining / 1000)}s remaining`;
  }
  
  onScanComplete(file) {
    this.scannerStatus.innerHTML = `<i class="fas fa-check-circle"></i> Scan complete for "${file.name}"`;
    
    // Simulate scan result (18% chance of infection)
    const infected = Math.random() < 0.18;
    const warning = !infected && Math.random() < 0.3; // 30% chance of warning for clean files
    
    let resultClass, resultIcon, resultText, scanDetails;
    
    if (infected) {
      resultClass = 'result-infected';
      resultIcon = 'fas fa-virus';
      resultText = 'Malware Detected!';
      scanDetails = 'Our system found potential threats in this document.';
    } else if (warning) {
      resultClass = 'result-warning';
      resultIcon = 'fas fa-exclamation-triangle';
      resultText = 'Suspicious Elements Found';
      scanDetails = 'The document appears clean but contains some unusual elements.';
    } else {
      resultClass = 'result-clean';
      resultIcon = 'fas fa-shield-alt';
      resultText = 'No Threats Found';
      scanDetails = 'This document appears to be clean and safe.';
    }
    
    // Show scan result
    this.scanResult.innerHTML = `
      <i class="${resultIcon}"></i> ${resultText}
      <div class="result-detail">${scanDetails}</div>
    `;
    this.scanResult.className = `scan-result show ${resultClass}`;
    
    // Update scan meta
    const scanTime = new Date().toLocaleTimeString();
    this.scanMeta.innerHTML = `
      <span><i class="fas fa-clock"></i> Scanned at ${scanTime}</span>
      <span><i class="fas fa-barcode"></i> Scan ID: ${Math.random().toString(36).substring(2, 10).toUpperCase()}</span>
    `;
    
    // Update upload button for next scan
    this.uploadLabel.querySelector('.btn-text').textContent = 'Scan Another Document';
  }
  
  showError(message) {
    this.scanResult.innerHTML = `<i class="fas fa-times-circle"></i> ${message}`;
    this.scanResult.className = 'scan-result show result-infected';
    this.scannerStatus.textContent = 'Scan aborted';
    this.progressPercent.textContent = '0%';
    this.timeRemaining.textContent = '';
  }
  
  resetUI() {
    this.filenameDisplay.textContent = '';
    this.fileDetails.innerHTML = '';
    this.scannerStatus.textContent = '';
    this.progressBar.style.width = '0%';
    this.progressPercent.textContent = '0%';
    this.timeRemaining.textContent = '';
    this.scanResult.textContent = '';
    this.scanResult.className = 'scan-result';
    this.scanMeta.innerHTML = '';
    
    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }
  }
  
  formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }
  
  getFileType(mimeType) {
    const types = {
      'application/pdf': 'PDF',
      'application/msword': 'DOC',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'DOCX',
      'text/plain': 'TXT',
      'application/rtf': 'RTF',
      'application/vnd.ms-excel': 'XLS',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'XLSX',
      'application/vnd.ms-powerpoint': 'PPT',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'PPTX'
    };
    return types[mimeType] || mimeType;
  }
}

// Initialize the scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new DocumentScanner();
});