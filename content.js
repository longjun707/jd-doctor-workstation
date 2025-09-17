// content.js

(function() {
  // 1. Inject the page script
  try {
    const script = document.createElement('script');
    // After bundling with Webpack, the output is a standard script, not an ES module.
    // script.type = 'module'; // This line must be removed.
    script.src = chrome.runtime.getURL('page/main.bundle.js');
    
    (document.head || document.documentElement).appendChild(script);
    
    script.onload = () => {
      // The script can be removed from the DOM after it has been loaded.
      script.remove();
    };

    script.onerror = (e) => {
      // Errors are not logged in production.
    }
  } catch (e) {
    // Errors are not logged in production.
  }

  // 2. Bridge messages between the page script and the background script
  window.addEventListener('message', (event) => {
    // We only accept messages from ourselves
    if (event.source === window && event.data.type === 'VALIDATE_DOCTOR_REQUEST') {
      chrome.runtime.sendMessage({
        action: 'validateDoctor',
        doctorName: event.data.payload.doctorName
      }, (response) => {
        // Send the response back to the page script
        window.postMessage({
          type: 'VALIDATION_RESULT',
          requestId: event.data.requestId,
          payload: response
        }, '*');
      });
    }

    // Bridge for updating order count
    if (event.source === window && event.data.type === 'UPDATE_ORDER_COUNT_REQUEST') {
      chrome.runtime.sendMessage({
        action: 'updateOrderCount',
        doctorName: event.data.payload.doctorName,
        count: event.data.payload.count
      });
    }
  });

})();
