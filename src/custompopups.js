(function() {
    // Keep track of the original window.open method
    var originalOpen = window.open;
  
    // Override the window.open method with our custom implementation
    window.open = function(url, name, specs) {
      // Extract the width and height specifications from the "specs" parameter
      var width = specs && specs.width ? specs.width : 500;
      var height = specs && specs.height ? specs.height : 500;
      var resizable = specs && specs.resizable !== undefined ? specs.resizable : true;
      name ||= "new window"
  
      // Create a new window element with the specified width and height
      var popup = document.createElement('div');
      popup.classList.add('popup');
      popup.style.width = width + 'px';
      popup.style.height = height + 'px';
      if (specs.initialY) popup.style.top = specs.initialY - parseInt(popup.style.height)/2 + "px"
      if (specs.initialX) popup.style.left = specs.initialX - parseInt(popup.style.width)/2 + "px"
      if (specs.initialX || specs.initialY) {
        popup.style.transform = "scale(0)"
        popup.style.transition = "top .25s, left .25s, transform .25s"
        setTimeout(() => {
          popup.style.top = "50px"
          popup.style.left = "50px"
          popup.style.transform = "scale(1)"
          setTimeout(() => popup.style.transition = "", 250)
        }, 1)
      }
  
      // Create a top bar element for the window
      var topBar = document.createElement('div');
      topBar.classList.add('popup-top-bar');
  
      // Create a title element for the top bar
      var title = document.createElement('div');
      title.classList.add('popup-title');
      title.textContent = name;
      topBar.appendChild(title);
  
      // Create a close button for the top bar
      var closeButton = document.createElement('button');
      closeButton.classList.add('popup-close-button');
      closeButton.innerHTML = '<span>&#x2715;</span>';
      closeButton.addEventListener('click', function() {
        iframe.contentWindow.close();
      });
      topBar.appendChild(closeButton);
  
      // Add the top bar to the window element
      popup.appendChild(topBar);
  
      // Create a new iframe element for the window
      var iframe = document.createElement('iframe');
      iframe.setAttribute('src', url);
      iframe.setAttribute('name', name);
      iframe.setAttribute('frameborder', '0');
      iframe.style.width = width + "px"
      iframe.style.height = (height - 30) + "px"
      iframe.style.padding = "0px 2.5px 2.5px"
  
      // Add the iframe to the window element
      popup.appendChild(iframe);
  
      // Add the window to the page
      document.body.appendChild(popup);
  
      // Make the window draggable
      var isDragging = false;
      var dragX, dragY;
      topBar.addEventListener('mousedown', function(event) {
        if (resizeEdge) return
        isDragging = true;
        dragX = event.clientX - popup.offsetLeft;
        dragY = event.clientY - popup.offsetTop;
  
        // Disable iframe interaction while dragging
        iframe.style.pointerEvents = 'none';
      });
      window.addEventListener('mousemove', function(event) {
        if (isDragging) {
          popup.style.left = (event.clientX - dragX) + 'px';
          popup.style.top = (event.clientY - dragY) + 'px';
        }
      });
      document.addEventListener('mouseup', function(event) {
        isDragging = false;
  
        // Re-enable iframe interaction when done dragging
        iframe.style.pointerEvents = 'auto';
        if(iframe.contentWindow)iframe.contentWindow.focus()
      });
      popup.addEventListener('mouseleave', function(event) {
        if (event.target == popup) return
        isDragging = false;
      });
  
      // Override the window.close method with our custom implementation
      var originalClose = iframe.contentWindow.close;
      iframe.contentWindow.close = function() {
        if (!popup.parentElement) return
        // Remove the window from the page
        // Animation
        if (specs.initialX || specs.initialY) {
          popup.style.transform = "scale(1)"
          popup.style.transition = "top .25s, left .25s, transform .25s"
          setTimeout(() => {
            popup.style.top = specs.initialY - parseInt(popup.style.height)/2 + "px"
            popup.style.left = specs.initialX - parseInt(popup.style.width)/2 + "px"
            popup.style.transform = "scale(0)"
            setTimeout(() => document.body.removeChild(popup), 250)
          }, 1)
        }
        // Call the original window.close method
        originalClose.call(iframe.contentWindow);
      };
  
      // Resize the window and fire the resize event listener when the popup is resized
      var resizePopup = function() {
        var newWidth = popup.offsetWidth;
        var newHeight = popup.offsetHeight;
        iframe.style.width = newWidth + 'px';
        iframe.style.height = (newHeight - 30) + 'px';
  
        // Fire the resize event listener
        var resizeEvent = new Event('resize');
        iframe.contentWindow.dispatchEvent(resizeEvent);
      }
  
      popup.addEventListener('resize', resizePopup);
  
      // Override the window.resizeTo method with our custom implementation
      var originalResizeTo = iframe.contentWindow.resizeTo;
      iframe.contentWindow.resizeTo = function(width, height) {
        // Resize the popup window
        width ||= parseInt(popup.style.width)
        height ||= parseInt(popup.style.height)
        width = Math.max(width, 150)
        height = Math.max(height, 150)
        popup.style.width = width + 'px';
        popup.style.height = height + 'px';
  
        // Fire the resize event listener
        resizePopup();
  
        // Call the original window.resizeTo method
        originalResizeTo.call(iframe.contentWindow, width, height);
      };
  
      iframe.contentWindow.focus()
      
      let isResizing = false;
      let resizeEdge = null;
  
      popup.addEventListener('mousemove', function(e) {
        if (isResizing) return
        const rect = this.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
  
        if (x < 5 && y < 5) {
          this.style.cursor = 'nw-resize';
          resizeEdge = 'top-left';
        } else if (x > rect.width - 5 && y < 5) {
          this.style.cursor = 'ne-resize';
          resizeEdge = 'top-right';
        } else if (x < 5 && y > rect.height - 5) {
          this.style.cursor = 'sw-resize';
          resizeEdge = 'bottom-left';
        } else if (x > rect.width - 5 && y > rect.height - 5) {
          this.style.cursor = 'se-resize';
          resizeEdge = 'bottom-right';
        } else if (x < 5) {
          this.style.cursor = 'w-resize';
          resizeEdge = 'left';
        } else if (x > rect.width - 5) {
          this.style.cursor = 'e-resize';
          resizeEdge = 'right';
        } else if (y < 5) {
          this.style.cursor = 'n-resize';
          resizeEdge = 'top';
        } else if (y > rect.height - 5) {
          this.style.cursor = 's-resize';
          resizeEdge = 'bottom';
        } else {
          this.style.cursor = 'default';
          resizeEdge = null;
        }
        topBar.style.cursor = this.style.cursor == "default" ? "move" : this.style.cursor
      });
  
      popup.addEventListener('mousedown', function(e) {
        if (resizeEdge) {
          isResizing = true;
          iframe.style.pointerEvents = 'none';
        }
      });
  
      document.addEventListener('mousemove', function(e) {
        if (isResizing) {
          e.preventDefault();
          const rect = popup.getBoundingClientRect();
          const x = e.clientX - rect.left;
          const y = e.clientY - rect.top;
          const dx = e.movementX;
          const dy = e.movementY;
          console.log(resizeEdge)
          if (resizeEdge === 'top-left') {
            iframe.contentWindow.resizeTo(rect.width - dx, rect.height - dy)
            popup.style.left = `${rect.left + dx}px`;
            popup.style.top = `${rect.top + dy}px`;
          } else if (resizeEdge === 'top-right') {
            iframe.contentWindow.resizeTo(rect.width + dx, rect.height - dy)
            popup.style.top = `${rect.top + dy}px`;
          } else if (resizeEdge === 'bottom-left') {
            iframe.contentWindow.resizeTo(rect.width - dx, rect.height + dy)
            popup.style.left = `${rect.left + dx}px`;
          } else if (resizeEdge === 'bottom-right') {
            iframe.contentWindow.resizeTo(rect.width + dx, rect.height + dy)
          } else if (resizeEdge === 'left') {
            iframe.contentWindow.resizeTo(rect.width - dx, null)
            popup.style.left = `${rect.left + dx}px`;
          } else if (resizeEdge === 'right') {
            iframe.contentWindow.resizeTo(rect.width + dx, null)
          } else if (resizeEdge === 'top') {
            iframe.contentWindow.resizeTo(null, rect.height - dy)
            popup.style.height = `${rect.height - dy}px`;
            popup.style.top = `${rect.top + dy}px`;
          }
           else if (resizeEdge === 'bottom') {
            iframe.contentWindow.resizeTo(null, rect.height + dy)
          }
        }
      })
  
      document.addEventListener('mouseup', function(e) {
        if (isResizing) {
          isResizing = false;
          resizeEdge = null;
          iframe.style.pointerEvents = 'auto';
        }
      });
  
      return iframe.contentWindow;
    };
    var style = document.createElement('style');
    style.innerHTML = '.popup{position:fixed;top:50px;left:50px;z-index:9999;background-color:#fff;border:1px solid #ddd;box-shadow:2px 2px 20px rgba(0,0,0,.7);transform-origin: center center;}.popup-top-bar{user-select: none;height:30px;background-color:#eee;cursor:move;display:flex;align-items:center}.popup-title{font-family:sans-serif;font-weight:bold;flex-grow:1;padding:0 10px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}.popup-close-button{margin:5px;padding:0;width:30px;height:30px;color:#fff;background-color:transparent;border:none;font-size:16px;font-weight:bold;text-align:center;line-height:1;cursor:pointer;transition:background-color .2s,color .2s;color:black;}.popup-close-button:hover{background-color:#f04747;color:white;}';
    document.head.appendChild(style);
  
  })();