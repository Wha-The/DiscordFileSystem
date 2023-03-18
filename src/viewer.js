JQueryNotLoadedHelp = "Please refresh your page or contact the server owner"
$ = window.$ || alert("JQuery was not properly loaded! " + JQueryNotLoadedHelp)
ws = null;
expectedstatus = "disconnected"

function disconnect() {
    expectedstatus = "disconnected"
    document.getElementById("status").innerHTML = "Disconnected"
    if (ws) {
        ws.close()
        ws = null
    }
}
systemFilenames = [
    ".."
]
SAVED_CWD = "/"
Settings = [
    document.getElementById("settings_autoconnect"),
    document.getElementById("settings_temporarysession"),
]
CURRENTSETTINGS = {}

function save_settings() {
    ToBeSaved = {}
    for (i = 0; i < Settings.length; i++) {
        currentelem = Settings[i]
        ToBeSaved[currentelem.id] = currentelem.checked
    }
    CookieManager.setCookie("filesystem_settings", JSON.stringify(ToBeSaved), 1)
    CURRENTSETTINGS = ToBeSaved
    showsnack("Changes Saved", 1000)
}

function load_settings() {
    Settings_raw = CookieManager.getCookie("filesystem_settings")
    if (Settings_raw != "") {
        Loaded_settings = JSON.parse(Settings_raw)
        CURRENTSETTINGS = Loaded_settings
        Object.keys(Loaded_settings).forEach(function(key) {
            checked = Loaded_settings[key]
            if (checked != null) {
                if (document.getElementById(key)) document.getElementById(key).checked = checked
            }
        })

        return Loaded_settings
    }
    return {};
}
loadedfuncfinished = Scripts.runAfterLoaded("CookieManager", function() {
    var settings = load_settings()
    if (settings["settings_autoconnect"]) {
        connect()
    }
    window.addEventListener("beforeunload", function(e) {
        var settings = load_settings()
        if ((settings["settings_temporarysession"] == undefined) || (settings["settings_temporarysession"] == true)) {
            CookieManager.setCookie("FileSystem_SessionInfo", "")
        }
    }, false);
})

function get_fname_icon_class(filename, isfolder) {
    var dotslips = filename.split(".")
    var ext = !isfolder && (dotslips[dotslips.length - 1] || "unknown") || "folder"
    var iconcode = "fa fa-file-o"
    var icons = {
        "folder": "fa fa-folder",
        "txt": "fa fa-file-text-o",
        "note": "fa fa-sticky-note-o",
        "docx": "fa fa-file-word-o",
        "pdf": "fa fa-file-pdf-o",
        "pptx": "fa fa-file-powerpoint-o",

        "py": "fa fa-file-code-o",
        "html": "fa fa-file-code-o",
        "js": "fa fa-file-code-o",
        "css": "fa fa-file-code-o",

        "mp4": "fa fa-file-video-o",
        "mov": "fa fa-file-video-o",

        "mp3": "fa fa-file-audio-o",
        "ogg": "fa fa-file-code-o",

        "png": "fa fa-file-image-o",
        "webp": "fa fa-file-image-o",
        "jpg": "fa fa-file-image-o",
        "jpeg": "fa fa-file-image-o",
        "gif": "fa fa-file-image-o",

        "zip": "fa fa-file-archive-o",
    }
    if (icons[ext.toLowerCase()]) {
        iconcode = icons[ext.toLowerCase()]
    }
    return iconcode
}

function updateFilesList(files, drive, cwd) {
    if (cwd != "/") files.unshift({
        "name": "..",
        "isfile": false
    })
    document.getElementById("cwd").innerHTML = cwd
    document.getElementById("drive").innerHTML = drive + ":"
    window.history.pushState("", "", '/filesystem' + cwd);
    SAVED_CWD = cwd
    div = document.getElementById("files-list")
    fileListData = ""
    for (i = 0; i < files.length; i++) {
        var current = files[i]
        var currentAdd = ""
        var iconcode = get_fname_icon_class(current.name, !current.isfile)

        if (current.protected) {
            iconcode = "fa fa-lock"
        }
        allfilestring = []
        currentfileindex = 0
        if (current.filesinside) {
            current.filesinside.forEach(function(file) {
                if (currentfileindex == 3) {
                    allfilestring.push("...")
                } else if (currentfileindex > 3) {
                    return
                } else {
                    allfilestring.push(file)
                }
                currentfileindex = currentfileindex + 1
            })
        }
        // currentAdd = "<li isfile='"+((current.isfile&&2||1)-1)+"' filename='"+current.name+"' class='noSelect'>"+extcode+" <font id='filename'>"+current.name+"</font>"+(systemFilenames.includes(current.name)&&"<font class='left_25'>System Path</font>"||
        // `<font class="left_25">Size: `+current.size+`</font>
        // `+
        // (current.protected&&"<font class='left_50'>Hidden</font>"||(current.filesinside&&current.filesinside.length>0 && `<font class="left_50">Files: [`+current.filesinside.length+`] `+allfilestring.join("<b>, </b>")+"</font>"||"<font class='left_50'></font>"))
        // +"</p>"	

        // )
        currentAdd = `<li class='fjs-item ${!current.isfile && "fjs-has-children" || ""}' data-isfile='${((current.isfile&&2||1)-1)}' data-filename='${current.name}' data-last-modified='${current.lastmodified}' data-fsize='${current.size}' id='file_${current.name}'>
					<a tabindex="-1" ondblclick='doubleclick(event, this.parentElement)' onclick='select("${current.name}")'>
						<span>
							<i class="${iconcode}"></i>
							<p>${current.name}</p>
						</span>
						${!systemFilenames.includes(current.name) && !current.isfile && "<i class='fa fa-caret-right'></i>" ||""}
						${systemFilenames.includes(current.name) && "<i class='fa fa-caret-left'></i>" ||""}
					</a>
				</li>`

        fileListData = fileListData + "\n" + currentAdd
    }
    div.innerHTML = fileListData
}

function link_enter_button(target, callback) {
    target.addEventListener("keyup", function(event) {
        value = target.value
        event.preventDefault();
        setTimeout(function() {
            if (event.keyCode === 13) {
                callback(value);
            }
        }, 25)
    });
}

function gobacktopath(p) {
    console.log("GOING BACK TO PATH: ", p)
    let inner = function(fcall) {
        setTimeout(() => {
            if (SAVED_CWD != p) return inner(fcall)
            return fcall()
        }, 200)
        cd("..")
    }
    return new Promise((resolve, reject) => {
        inner(resolve)
    })
}
async function gotopath(path) {
    if (typeof path == "string") path = path.split(/\//g)
    var cwd_path = SAVED_CWD.split(/\//g)
    var goBackToPath = [""]
    cwd_path.forEach((seg, index) => {
        if (path[index] != seg) {
            goBackToPath = path.slice(0, index - 1)
        }
    })
    goBackToPath = "/" + goBackToPath.join("/")
    await gobacktopath(goBackToPath)
    path.forEach(function(segment) {

        if (segment) {
            console.log(segment)
            cd(segment)
        }
    })
}
REFRESH_AFTERFUNC = null

function _connect(reconnection) {
    if (reconnection) {
        console.log("reconnection")
    }
    document.getElementById("status").innerHTML = "Connecting..."
    ws = {}
    try {
        wss = new WebSocket("ws" + (window.location.protocol == "https:" && "s" || "") + "://" + location.host + "/api/websocket");
    } catch (e) {
        ws = null
        document.getElementById("errmsg").innerHTML = "Connection attempt failed!"
        return
    }

    wss.onopen = function() {
        document.getElementById("status").innerHTML = "Connected"
        expectedstatus = "live"
        gotopath(decodeURIComponent(location.pathname).split(/\//g).slice(2))
    };
    var sounds = {
        click: new Audio('/resource?filename=click.mp3'),
        error: new Audio('/resource?filename=error.mp3'),
    }
    ws.onmessage = function(evt) {
        document.getElementById("status").innerHTML = "Connected"
        response = JSON.parse(evt.data)
        error = response.error
        redirect = response.redirect
        console.log(response)
        if (error) {
            document.getElementById("errmsg").innerHTML = error
        } else if (redirect) {
            window.location.href = redirect
        } else {
            content = response.content
            previousAction = response.action
            if (previousAction == "cd") {
                if (response.passwordRequired) {
                    if (response.passwordIncorrect) alert("Incorrect password")
                    // document.getElementById("overlay_text").innerHTML = `
                    // Password Required: Please enter the password to this directory.
                    // <br>
                    // <input type="password" id='cd_password_input' placeholder="password" autocomplete="off" autocorrect="off" autocapitalize="off"><br>
                    // <button onclick="document.getElementById('overlay').style.display = 'none';">Close</button>
                    // <button onclick='cd("`+response.cd+`",document.getElementById("cd_password_input").value)' id="cd_password_input_button">CD</button>
                    // `
                    // input = document.getElementById("cd_password_input")
                    // link_enter_button(input,function(value){	
                    // 	cd(response.cd,value)
                    // })
                    // document.getElementById("overlay").style.display = "block"
                    // input.focus()
                    var value = prompt("Password Required: Enter password for " + (SAVED_CWD + response.cd))
                    if (value) cd(response.cd, value)
                } else {
                    sounds.click.play();
                    document.getElementById('overlay').style.display = 'none';
                    ws.send(JSON.stringify({
                        "action": "getCDContents"
                    }))
                }
            }
            if (previousAction == "getCDContents") {

                updateFilesList(response.files, response.drive, response.cwd)
                if (response.afterselect) {
                    SELECTED = response.afterselect
                } else {
                    SELECTED = null
                }
                update()
                if (REFRESH_AFTERFUNC) {
                    REFRESH_AFTERFUNC()
                    REFRESH_AFTERFUNC = null
                }
            }
            if (previousAction == "delFile") {
                refreshDirectory()
                SELECTED = null
                update()
            }
            if (previousAction == "downloadFile") {
                console.log(response.progress)
                monitorFileProgress(response.filename, response.progress, onconnect = () => {
                    var iframe = document.createElement("iframe")
                    iframe.src = response.url
                    iframe.style.display = "none"
                    document.body.appendChild(iframe)
                })
            }
            if (previousAction == "newFolder") {
                if (response.afterselect) {
                    afselect = response.afterselect
                    refreshDirectory(null, function() {
                        select(afselect)
                        rename(afselect)
                    })
                }
            }
        }
    }

    wss.onclose = function() {
        document.getElementById("status").innerHTML = "Disconnected"
        if (expectedstatus != "disconnected") {
            connect(true)
        }
    }
    wss.onmessage = function(evt) {
        (async () => {
            while (!window.hasOwnProperty("ENCRYPTION_READY"))
                await new Promise(resolve => setTimeout(resolve, 10));
            ws.onmessage({
                "data": window.client_decrypt(evt.data),
            })
        })();
    }
    ws.send = function(data) {
        (async () => {
            while (!window.hasOwnProperty("ENCRYPTION_READY"))
                await new Promise(resolve => setTimeout(resolve, 10));
            wss.send(window.client_encrypt(data))
        })();
    }
    ws.close = () => wss.close
};

function connect(reconnection) {
    (async () => {
        while (!window.hasOwnProperty("ENCRYPTION_READY"))
            await new Promise(resolve => setTimeout(resolve, 10));
        _connect(reconnection)
    })();
}
SELECTED = null

function pingws(noalert) {
    if (!ws) {
        if (!noalert) alert("Please connect to the server.")
        return false
    }
    return true
}


function cd(dir, password) {
    if (!pingws()) return
    try {
        if (!popup.closed) {
            alert("Popup window is still open. You must close it to change your directory.");
            return
        }
    } catch (e) {

    }

    dir = dir || SELECTED
    if (dir) {
        data = JSON.stringify({
            "action": "cd",
            "data": {
                "dir": dir,
                "password": password
            }
        })
        console.log("CD SEND DATA: " + data)
        ws.send(data)
    }
}

function download() {
    if (!pingws()) return
    ws.send(JSON.stringify({
        "action": "downloadFile",
        "data": {
            "file": SELECTED || SAVED_CWD
        }
    }))
}

function upload() {
    document.getElementById("file-input").click()
}

function rename(file) {
    elem = document.getElementById("file_" + file)
    origInnerHtml = elem.innerHTML
    elem.innerHTML = "<input type='text' id='rename_" + file + "' value='" + elem.getAttribute("data-filename") + "' placeholder='new name' style='width:100%;max-width:100%'>"
    renameelem = document.getElementById("rename_" + file)
    renameelem.select()
    renameelem.addEventListener("keyup", function(event) {
        event.preventDefault();
        // Number 13 is the "Enter" key on the keyboard
        setTimeout(function() {
            if (event.keyCode === 13) {
                // Cancel the default action, if needed

                after = renameelem.value
                ws.send(JSON.stringify({
                    action: "renFile",
                    data: {
                        from: file,
                        to: after
                    }
                }))
                refreshDirectory(after)

            }
            if (event.keyCode === 27) { // esc
                elem.innerHTML = origInnerHtml
            }
        }, 25)
    });
}

function editAddressBar() {
    if (document.getElementById("edit_cwd")) return
    elem = document.getElementById("cwd")
    origInnerHtml = elem.innerHTML
    elem.innerHTML = "<input type='text' id='edit_cwd' value='" + elem.innerHTML + "' placeholder='new name' style='flex-grow:1; font-size:1em;'>"

    renameelem = document.getElementById("edit_cwd")
    renameelem.select()
    renameelem.onblur = () => {
        elem.innerHTML = origInnerHtml
    }
    renameelem.addEventListener("keyup", function(event) {
        event.preventDefault();
        // Number 13 is the "Enter" key on the keyboard
        setTimeout(function() {
            if (event.keyCode === 13) {
                // Cancel the default action, if needed
                after = renameelem.value
                renameelem.onblur = () => {}
                gotopath(after)
            }
            if (event.keyCode === 27) { // esc
                elem.innerHTML = origInnerHtml
            }
        }, 25)
    });
}
recentdoubleclick = false

function select(file) {
    if (!pingws()) return
    if (recentdoubleclick) {
        recentdoubleclick = false
        return
    }
    if (SELECTED == file) {
        if (systemFilenames.includes(file)) {
            return
        }

    } else {
        SELECTED = file
        update()
    }
}

function getFileDownloadLink(fname, finish, doNotMonitor) {
    if (!pingws()) return
    var OLDWSONMESSAGEHANDLER = ws.onmessage
    var retrievedData = null
    ws.onmessage = function(data) {
        response = JSON.parse(data.data)
        if (response.url) {
            ws.onmessage = OLDWSONMESSAGEHANDLER
            if (!doNotMonitor) monitorFileProgress(response.filename, response.progress)
            finish(response.url)
        }
    }
    ws.send(JSON.stringify({
        "action": "downloadFile",
        "data": {
            "file": fname
        }
    }))
}

function getFileContents(fname, finish, doNotMonitor) {
    if (!pingws()) return
    getFileDownloadLink(fname, function(redirect) {
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (this.readyState == 4 && this.status == 200) {
                this.response.text().then(finish)
            }
        }
        xhr.open('GET', redirect);
        xhr.responseType = 'blob';
        xhr.send();
    }, doNotMonitor)
}

function getFileContentsAsDataUrl(fname, finish, doNotMonitor) {
    if (!pingws()) return
    getFileDownloadLink(fname, function(redirect) {
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (this.readyState == 4 && this.status == 200) {
                finish(URL.createObjectURL(new Blob([this.response])))
            }
        }
        xhr.open('GET', redirect);
        xhr.responseType = 'blob';
        xhr.send();
    }, doNotMonitor)
}
var edit_callbacks = {
    ".txt": edittxt,
    ".note": edittxt,

    ".mp4": editmp4,
    ".mov": editmp4,

    ".mp3": editmp3,
    ".ogg": editmp3,

    ".png": editpng,
    ".webp": editpng,
    ".jpg": editpng,
    ".jpeg": editpng,
    ".gif": editpng,
}

function edit(evt) {
    var s = SELECTED.toLowerCase()
    Object.entries(edit_callbacks).forEach(x => {
        var suffix = x[0],
            callback = x[1]
        if (s.endsWith(suffix)) callback()
    })
}

var _last_popup
function setup_popup(popup) {
    // var lsn = () => {
    //     popup.close()
    // }
    // window.addEventListener("beforeunload", lsn)
    // popup.addEventListener("beforeunload", () => window.removeEventListener("beforeunload", lsn))
    if(_last_popup && _last_popup != popup) _last_popup.close()
    _last_popup = popup
}

function editmp3() {
    var load_fname = SELECTED
    getFileContentsAsDataUrl(load_fname, function(url) {
    	var popFrom = document.getElementById("file_"+load_fname).getBoundingClientRect()
        popup = window.open(" ", "Audio Player", {width: 325, height:150, initialX: popFrom.left + 50, initialY: popFrom.top + popFrom.height/2})
        writedata = `
<title>Audio Player</title>
<body style="margin: 0 0 0 0">
<div class="fjs-list" style="margin-left: 5px"><li class="fjs-item" id="f_filename"></li></div>
<audio controls width="100%" height="100%" id="player">
    <source src="${url}"
            type="audio/mp3">

    Sorry, your browser doesn't support embedded audio.
</audio>
<label style="display: block;"><input type="checkbox" id="bool_loop"> <b style="font-family: sans-serif;">Loop</b></label>
<label><input type="checkbox" id="bool_autoplay"> <b style="font-family: sans-serif;">Autoplay</b></label> <b>(<a style="color: blue; text-decoration: underline; cursor: pointer;" id="forceskip" class="noselect">skip</a>)</b>
<scr` + `ipt>
navigator.mediaSession.setActionHandler('previoustrack', function() {
	do_skip(true)
});
navigator.mediaSession.setActionHandler('nexttrack', function() {
	do_skip()
});
</scr` + `ipt>

</body>
				`
        popup.$ = $
        popup.document.write(writedata)
        Array.from(document.querySelectorAll(".childWindowsInherit"), (e) => {
            var c = popup.document.createElement(e.nodeName)
            c.innerHTML = e.innerHTML
            Array.from(e.attributes).forEach(({
                name,
                value
            }) => {
                c.setAttribute(name, value)
            })
            popup.document.head.appendChild(c)
        })
        popup.document.getElementById("f_filename").innerHTML = `<i class="${get_fname_icon_class(load_fname)}" style="padding-right: 5px;"></i>${load_fname}`
        popup.document.title = load_fname
        var v = popup.document.getElementById("player")
        var seekedRecently = false
        v.onseeked = () => {
            if (seekedRecently) clearTimeout(seekedRecently)
            seekedRecently = setTimeout(() => {
                seekedRecently = false
            }, 100)
        }
        popup.do_skip = (back) => {
            popup.document.getElementById("forceskip").innerHTML = "..."
            if (!SELECTED) select(popup.document.title)
            while (relselectmove(back && -1 || 1) && !SELECTED.endsWith(".mp3")) {}
            if (SELECTED.endsWith(".mp3")) {
                getFileContentsAsDataUrl(SELECTED, (url) => {
                    v.querySelector("source").src = url
                    v.load()
                    v.play()
                    popup.document.getElementById("forceskip").innerHTML = "skip"
                    load_fname = SELECTED
                    popup.document.getElementById("f_filename").innerHTML = `<i class="${get_fname_icon_class(SELECTED)}" style="padding-right: 5px;"></i>${SELECTED}`
                    popup.document.title = SELECTED
                })
            }
        }

        v.addEventListener("ended", function(e) {
            if (!seekedRecently && !popup.document.getElementById("bool_loop").checked && popup.document.getElementById("bool_autoplay").checked) {
                popup.do_skip()
            }
        })
        popup.document.getElementById("forceskip").addEventListener("click", (event) => popup.do_skip(event.shiftKey))
        popup.document.getElementById("bool_loop").addEventListener('change', (event) => v[(event.currentTarget.checked && "setAttribute" || "removeAttribute")]("loop", true))
        popup.document.addEventListener("keydown", function(event){
        	if (event.target.nodeName == "INPUT" || event.target.nodeName == "AUDIO") return
        	if (event.code == "Space"){
        		event.preventDefault()
        		v.paused ? v.play() : v.pause()
        	}
        	if (event.code == "KeyL"){
        		event.preventDefault()
        		popup.document.getElementById("bool_loop").click()
        	}
        	if (event.code == "KeyA"){
        		event.preventDefault()
        		popup.document.getElementById("bool_autoplay").click()
        	}
        })
        setup_popup(popup)
    })
}

function editpng() {
	var load_fname = SELECTED
    getFileDownloadLink(SELECTED, function(url) {
    	var popFrom = document.getElementById("file_"+load_fname).getBoundingClientRect()
        popup = window.open(" ", "Image Viewer", {width:145, height:145, initialX: popFrom.left + 50, initialY: popFrom.top + popFrom.height/2})
        writedata = `
	<body style="margin: 0 0 0 0">
		<title>Image Viewer</title>
		<img width=100% height=100% style="object-fit: contain;" id="image" class="noselect" draggable="false">
	</body>
				`
        popup.$ = $
        popup.document.write(writedata)
        var img = popup.document.getElementById("image")
        var WIDTH_SET = 600
        var _loadImage = function(url) {
            img.setAttribute("loading", true)
            img.src = url
            img.onload = function() {
                var w = Math.min(WIDTH_SET, this.naturalWidth)
                img.style.filter = ""
                popup.resizeTo(w, (w / this.naturalWidth) * this.naturalHeight)
                img.removeAttribute("loading")
            }
        }
        _loadImage(url)
        popup.document.addEventListener("keydown", function(event) {
            if (event.code == "Space") {
                event.preventDefault()
                popup.close()
            } else {
                var _old_SELECTED = SELECTED
                main_document_onkeypress(event)
                if (_old_SELECTED != SELECTED) {
                    img.style.filter = "brightness(25%)"
                    getFileDownloadLink(SELECTED, _loadImage)
                }
            }
        })
        popup.addEventListener('resize', function() {
            if (img.getAttribute("loading")) return
            WIDTH_SET = this.width
        });
        setup_popup(popup)
    })

}

function editmp4() {
	var load_fname = SELECTED
    getFileContentsAsDataUrl(SELECTED, function(url) {
    	var popFrom = document.getElementById("file_"+load_fname).getBoundingClientRect()
        popup = window.open("", "Video Player", {width: 1000, height: 500, initialX: popFrom.left + 50, initialY: popFrom.top + popFrom.height/2})
        writedata = `
<title>Video Player</title>
<body style="margin: 0 0 0 0">
<video controls width="100%" height="100%" id="player">

    <source src="` + url + `"
            type="video/mp4">

    Sorry, your browser doesn't support embedded videos.
</video>
</body>
				`
        popup.$ = $
        popup.document.write(writedata)
        var v = popup.document.getElementById("player");
        v.addEventListener("loadedmetadata", function(e) {
            var width = this.videoWidth,
                height = this.videoHeight;
            popup.resizeTo(width, height)
        }, false);
        setup_popup(popup)
    })

}

function edittxt() {
    var currentFName = SELECTED
    getFileContents(SELECTED, function(data) {
    	var popFrom = document.getElementById("file_"+currentFName).getBoundingClientRect()
        popup = window.open("", "Editor", {width: 500, height:500, initialX: popFrom.left + 50, initialY: popFrom.top + popFrom.height/2})
        writedata = `
<title>Editor</title>
<style>
#snackbar {
  visibility: hidden;
  min-width: 250px;
  margin-left: -125px;
  background-color: #333;
  color: #fff;
  text-align: center;
  border-radius: 25px;
  padding: 16px;
  position: fixed;
  z-index: 1;
  left: 50%;
  bottom: 30px;
  font-size: 17px;
  font-family: Helvetica, Sans-Serif;
}

#snackbar.show {
  visibility: visible;
  -webkit-animation: fadein 0.5s, fadeout 0.5s 2.5s;
  animation: fadein 0.5s, fadeout 0.5s 2.5s;
}

</style>
<div class="fjs-list" style="margin-left: 5px"><li class="fjs-item"><i class="${get_fname_icon_class(currentFName)}" style="padding-right: 5px;"></i>${currentFName}</li></div>
<textarea style="width:100%;height:90%" id="editor">
` + data + `
</textarea>
<div id="snackbar">Some text some message..</div>
<sc` + `ript>
var saved = true
keydown = function(event) {
    if (event.ctrlKey || event.metaKey) {
        switch (String.fromCharCode(event.which).toLowerCase()) {
        case 's':
            event.preventDefault();
            save()
            break;
        case 'f':
            event.preventDefault();
            alert('ctrl-f');
            break;
        case 'g':
            event.preventDefault();
            alert('ctrl-g');
            break;
        }
    }
}
$(window).bind('keydown', keydown);
$("#editor").bind('keydown', keydown);
document.getElementById("editor").oninput = function(){
	saved = false
}

function showsnack(text, timeout) {
  var x = document.getElementById("snackbar");
  x.className = "show";
  x.innerHTML = text||x.innerHTML
  const close = function(){ x.className = x.className.replace("show", ""); }
  if(timeout!=false){
  	return setTimeout(close, timeout||3000);
  }
  return close

}

</sc` + `ript>
				`
        popup.$ = $
        popup.document.write(writedata)
        Array.from(document.querySelectorAll(".childWindowsInherit"), (e) => {
            var c = popup.document.createElement(e.nodeName)
            c.innerHTML = e.innerHTML
            Array.from(e.attributes).forEach(({
                name,
                value
            }) => {
                c.setAttribute(name, value)
            })
            popup.document.head.appendChild(c)
        })
        popup.addEventListener('beforeunload', function(e) {
            if (!popup.saved) {
                e.preventDefault();
                e.returnValue = 'Changes will not be saved';
            }
        });


        popup.save = function() {
            var data = popup.document.getElementById("editor").value
            var file = new File([data], currentFName, {
                lastModified: new Date(),
                type: "overide/mimetype"
            });
            var closePopup = popup.showsnack("Saving...", false)

            uploadSingleFile(file).then(() => {
                closePopup()
                popup.showsnack("Saved successfully")
                refreshDirectory(currentFName)
            })

            popup.saved = true
        }
        setup_popup(popup)
    })

}

function doubleclick(evt, elem) {
    evt.preventDefault()
    if (!pingws()) return
    recentdoubleclick = true
    fname = elem.getAttribute("data-filename")
    isfile = elem.getAttribute("data-isfile") == "1"
    if (isfile) {
        edit(fname)
    } else {
        cd(fname)
    }
}
(() => {
    var doeditaddrbar = function(evt) {
        evt.preventDefault()
        if (!pingws()) return
        editAddressBar()
    }
    document.getElementById("cwd").onclick = doeditaddrbar
    document.getElementById("drive").onclick = doeditaddrbar
})()

function createLeafRow(fname, fsize, iconhtml, lastModified) {
    var div = document.createElement("div")
    /* <div class="fjs-col leaf-col"><div class="leaf-row"><i class="fa fa-file-o"></i>.codeclimate.yml<div class="meta"><strong>Size: </strong>56 KB</div><div class="meta"><strong>Modified: </strong>02/21/2015 at 10:04am</div></div></div> */
    div.classList = "fjs-col leaf-col"
    div.id = "leafrow"
    var timeString = "???"
    if (lastModified != 0) {
        var lastModifiedDate = new Date(lastModified * 1000)
        var timeString = `${String(lastModifiedDate.getDate()).padStart(2, '0')}/${String(lastModifiedDate.getMonth()).padStart(2, '0')}/${String(1900 + lastModifiedDate.getYear()).padStart(4, '0')} at ${String(lastModifiedDate.getHours() % 12).padStart(2, '0')}:${String(lastModifiedDate.getMinutes()).padStart(2, '0')}${lastModifiedDate.getHours() >= 12 ? 'pm' : 'am'}`
    }
    if (iconhtml.includes("fa-file-image-o")) {
        // image: replace with preview
        iconhtml = `<img id="leaf_row_preview_image">`
        setTimeout(() => {
            if (SELECTED == fname) getFileDownloadLink(fname, (url) => {
                document.getElementById("leaf_row_preview_image").src = url
            }, true)
        }, 50)
    } else if (iconhtml.includes("fa-file-text-o") || iconhtml.includes("fa-sticky-note-o")) {
        iconhtml = `<textarea id="leaf_row_preview_textarea" readonly></textarea>`
        setTimeout(() => {
            if (SELECTED == fname) getFileContents(fname, (data) => {
                document.getElementById("leaf_row_preview_textarea").value = data
            }, true)
        }, 50)
    }

    div.innerHTML = `<div class="leaf-row">
				${iconhtml}
				${fname}
				<div class="meta">
					<strong>Size: </strong>${humanFileSize(fsize, si=true)}
				</div>
				<div class="meta">
					<strong>Modified: </strong>${timeString}
				</div>
			</div>`
    document.getElementById("files").appendChild(div)
    return div
}

function update() {
    if (!pingws()) return
    elems = document.getElementById("files-list").children
    for (i = 0; i < elems.length; i++) {
        elem = elems[i]
        if (elem.classList.contains("fjs-active")) {
            elem.classList.remove("fjs-active")
        }
    }
    actionbar_refersh = true
    actionbar_cd = false
    actionbar_download = true
    actionbar_edit = false
    actionbar_upload = true
    actionbar_newFolder = true
    actionbar_newFile = true
    actionbar_rename = false
    actionbar_delete = false
    var leafRow = document.getElementById("leafrow")
    if (leafRow) leafRow.parentElement.removeChild(leafRow)
    if (SELECTED) {
        elem = document.getElementById("file_" + SELECTED)
        leafRow = createLeafRow(SELECTED, elem.getAttribute("data-fsize"), elem.querySelector("i").outerHTML, elem.getAttribute("data-last-modified"))
        isfile = elem.getAttribute("data-isfile") == "1"
        elem.classList.add("fjs-active")
        actionbar_download = true
        actionbar_delete = true
        actionbar_rename = true
        if (isfile) {
            var canEdit = false;
            Object.entries(edit_callbacks).forEach(x => {
                var suffix = x[0]
                if (SELECTED.toLowerCase().endsWith(suffix)) {
                    canEdit = true
                }
            })
            if (canEdit) {
                actionbar_edit = true
            }
        } else {
            actionbar_cd = true
        }
    }
    if (systemFilenames.includes(SELECTED)) {
        actionbar_delete = false
        actionbar_download = false
        actionbar_rename = false
    }
    document.getElementById("actionbar_refresh")[actionbar_refersh && "removeAttribute" || "setAttribute"]("disabled", true)
    document.getElementById("actionbar_cd")[actionbar_cd && "removeAttribute" || "setAttribute"]("disabled", true)
    document.getElementById("actionbar_download")[actionbar_download && "removeAttribute" || "setAttribute"]("disabled", true)
    document.getElementById("actionbar_edit")[actionbar_edit && "removeAttribute" || "setAttribute"]("disabled", true)
    document.getElementById("actionbar_upload")[actionbar_upload && "removeAttribute" || "setAttribute"]("disabled", true)
    document.getElementById("actionbar_newFolder")[actionbar_newFolder && "removeAttribute" || "setAttribute"]("disabled", true)
    document.getElementById("actionbar_newFile")[actionbar_newFile && "removeAttribute" || "setAttribute"]("disabled", true)
    document.getElementById("actionbar_rename")[actionbar_rename && "removeAttribute" || "setAttribute"]("disabled", true)
    document.getElementById("actionbar_delete")[actionbar_delete && "removeAttribute" || "setAttribute"]("disabled", true)
}

function refreshDirectory(afterselect, afterfunc) {
    if (afterfunc) REFRESH_AFTERFUNC = afterfunc
    if (!pingws()) return
    ws.send(JSON.stringify({
        "action": "getCDContents",
        data: {
            afterselect: afterselect
        }
    }))
}
window.refreshDirectory = refreshDirectory

document.getElementById("actionbar_refresh").onclick = () => refreshDirectory()
document.getElementById("actionbar_cd").onclick = function() {
    cd()
}
document.getElementById("actionbar_download").onclick = download;
document.getElementById("actionbar_edit").onclick = edit;
document.getElementById("actionbar_upload").onclick = upload;
document.getElementById("actionbar_newFolder").onclick = function() {
    if (!pingws()) return
    ws.send(JSON.stringify({
        "action": "newFolder"
    }))
}
document.getElementById("actionbar_newFile").onclick = function() {
    if (!pingws()) return
    var file = new File([""], "Untitled.note", {
        lastModified: new Date(),
        type: "overide/mimetype"
    })
    uploadSingleFile(file).then(() => refreshDirectory("Untitled.note"))
}
document.getElementById("actionbar_delete").onclick = function() {
    if (confirm(`Are you sure you want to delete "${document.getElementById("file_"+SELECTED).getAttribute("data-filename")}"?`)) {
        ws.send(JSON.stringify({
            action: "delFile",
            data: {
                file: SELECTED
            }
        }))
    }
}

document.getElementById("actionbar_rename").onclick = function() {
    rename(SELECTED)
}
// upload monitoring
function monitorFileProgress(fname, pid, onconnect) {
    return new Promise((resolve, reject) => {
        var div = document.createElement("div")
        div.innerHTML = `<li class="fjs-item"><i class="${get_fname_icon_class(fname)}" style="padding-right: 5px;"></i>${fname}</li><div class="progress"><div class="progress-bar progress-bar-striped progress-bar-animated bg-primary" role="progressbar"></div></div>`
        div.className = "fjs-list"
        div.children[1].children[0].innerHTML = "0%"
        div.children[1].children[0].style.width = "0%"
        document.getElementById("fileUploadBars").appendChild(div)

        // pid: progress id
        var wss = new WebSocket("ws" + (window.location.protocol == "https:" && "s" || "") + "://" + location.host + "/api/file_progress_websocket");

        // wrappers
        var ws = {}
        wss.onmessage = (d) => ws.onmessage(window.client_decrypt(d.data)) // wrapper
        ws.send = (data) => wss.send(window.client_encrypt(data)) // wrapper

        wss.onopen = () => {
            ws.send(JSON.stringify({
                action: "ListenFileProgress",
                data: {
                    progressid: pid
                }
            }))
            if (onconnect) onconnect()
        }
        ws.onmessage = (data) => {
            data = JSON.parse(data)
            if (data.progress) {
                div.children[1].children[0].innerHTML = Math.round((data.progress * 100)) + "%"
                div.children[1].children[0].style.width = (data.progress * 100) + "%"
            }
            if (data.completed) {
                div.children[1].children[0].classList.remove("bg-primary")
                div.children[1].children[0].classList.add("bg-success")
                wss.close()
                setTimeout(() => div.parentElement.removeChild(div), 5000)
                return resolve()
            }
        }
    })

}
var contextMenu = document.getElementById("context-menu")
var context_menu_init = function() {
    var ul = contextMenu.querySelector("ul")
    ul.innerHTML = ""
    var ops = ["cd", "edit", "download", "rename"]
    ops.forEach((choice) => {
        var b = document.getElementById("actionbar_" + choice)
        if (!b.getAttribute("disabled")) {
            var li = document.createElement("li")
            var a = document.createElement("a")
            li.appendChild(a)
            a.innerHTML = b.innerHTML
            a.onclick = () => {
                contextMenu.classList.remove("context-menu-show")
                b.click()
            }
            ul.appendChild(li)

        }
    })
}
// Get the context menu element


// Show the context menu when the user right-clicks
document.getElementById("files-list").addEventListener("contextmenu", function(event) {
    event.preventDefault();
    if (contextMenu.classList.contains("context-menu-show")) {
        contextMenu.classList.remove("context-menu-show")
        return
    }
    var f_s = event.target.closest("li") && event.target.closest("li").classList.contains("fjs-item") && event.target.closest("li")
    if (f_s) {
        select(f_s.getAttribute("data-filename"))
    }
    contextMenu.style.left = event.clientX + "px";
    contextMenu.style.top = event.clientY + "px";
    contextMenu.classList.add("context-menu-show")
    context_menu_init()
});

// Hide the context menu when the user clicks outside of it
document.addEventListener("click", function(event) {
    if (event.target != contextMenu && !contextMenu.contains(event.target)) {
        contextMenu.classList.remove("context-menu-show")
    }
});

// uploading
fileinput = document.getElementById("file-input");
fileinput.addEventListener("change", handleFiles, false)

function uploadSingleFile(file, attemptNumber) {
    attemptNumber ||= 0
    return new Promise((resolve, reject) => {
        if (file.size >= (10485760000)) {
            return reject(alert("Unable to upload " + file.name + ":\nFile exceeds 10GB."))
        }

        let formData = new FormData();

        formData.append("file", file);
        formData.append("data", JSON.stringify({
            "path": SAVED_CWD,
            "last_modified": file.lastModified / 1000
        }));

        try {
            fetch('/api/upload', {
                method: "POST",
                body: formData
            }).then(function(r) {
                r.json().then((data) => {
                    if (data.success && data.progress) {
                        monitorFileProgress(file.name, data.progress).then(resolve).catch(reject)
                    }
                })
                console.log('HTTP response code:', r.status);
            });

        } catch (e) {
            console.log('Huston we have problem...:', e);
            if (attemptNumber >= 3) {
                return reject(alert("Unable to upload " + file.name + ":\n" + e))
            } else {
                uploadSingleFile(file, attemptNumber + 1).then(resolve).catch(reject)
            }
        }
    })
}

function handleFiles(files) {
    Array.from(files).forEach((f) => uploadSingleFile(f).then(() => refreshDirectory(f.name)))
}
var dragTimer;

function drop(e) {
    dropbox.classList.remove("specialborders")
    document.getElementById("overlay").style.display = "none";
    if (!pingws()) return
    const dt = e.originalEvent.dataTransfer;
    const files = dt.files;

    handleFiles(files)
}
dropbox = document.body
var dragTimer;
$(dropbox).on("dragenter dragstart dragend dragleave dragover drag drop", function(e) {
    e.preventDefault();
});
$(dropbox).on('dragover', function(e) {
    var dt = e.originalEvent.dataTransfer;
    if (dt.types && (dt.types.indexOf ? dt.types.indexOf('Files') != -1 : dt.types.contains('Files'))) {
        dropbox.classList.add("specialborders")
        document.getElementById("overlay").style.display = "block";
        document.getElementById("overlay_text").innerHTML = pingws(true) ? "Drop files to upload" : "Please connect to the server first"
        window.clearTimeout(dragTimer);
    }
});
$(dropbox).on('dragleave', function(e) {
    dragTimer = window.setTimeout(function() {
        dropbox.classList.remove("specialborders")
        document.getElementById("overlay").style.display = "none";
    }, 25);
});

$(dropbox).on("drop", drop)

var relselectmove = function(offset) {
    var s = document.getElementById("file_" + SELECTED)
    var i = Array.from(s.parentElement.children).indexOf(s)
    var n = s.parentElement.children
    n = n[i + offset]
    if (n) select(n.getAttribute("data-filename"))
    return n
}

document.body.addEventListener("click", function(e) {
    var elem = e.target;
    if (Array.from(document.querySelectorAll(".fjs-col")).includes(elem)) {
        SELECTED = null
        update()
    }
});
main_document_onkeypress = function(event) {
    if ((event.ctrlKey && event.code == "KeyF") || (event.code == "Escape" && event.target == document.getElementById("search-box"))) {
        event.preventDefault()
        var searchBoxContainer = document.getElementById("search-box-container")
        if (event.code == "Escape") {
            Array.from(document.querySelectorAll(".has-search-marks")).forEach((c) => {
                c.innerHTML = c.getAttribute("data-default-text")
                c.removeAttribute("data-default-text")
                c.classList.remove("has-search-marks")
            })
            searchBoxContainer.classList.remove("search-box-open");
            setTimeout(() => {
                searchBoxContainer.style.display = "none";
                document.getElementById("search-box").value = ""
            }, 100);
            return
        }
        // ctrl f
        if (searchBoxContainer.style.display === "none") {
            searchBoxContainer.style.display = "block";
            setTimeout(() => searchBoxContainer.classList.add("search-box-open"), 1);
        }
        document.getElementById("search-box").focus()
    }
    if (event.target.nodeName == "INPUT") return
    if (event.code == "Space") {
        if (SELECTED) event.preventDefault();
        edit(event)
    }
    if (event.code == "ArrowUp") {
    	event.preventDefault()
        if (SELECTED) {
            relselectmove(-1)
        } else {
        	if(!document.querySelector(".fjs-item")) return
            select(document.querySelector(".fjs-item").getAttribute("data-filename"))
        }
    }
    if (event.code == "ArrowDown") {
    	event.preventDefault()
        if (SELECTED) {
            event.preventDefault()
            relselectmove(1)
        } else {
        	if(!document.querySelector(".fjs-item")) return
            select(document.querySelector(".fjs-item").getAttribute("data-filename"))
        }
    }
    if (event.code == "Enter") {
    	if(SELECTED){
    		doubleclick(event, document.getElementById("file_"+SELECTED))
    	}
    }
}
var _search_process = () => {
	var search_box = document.getElementById("search-box")
    Array.from(document.querySelectorAll(".has-search-marks")).forEach((c) => {
        c.innerHTML = c.getAttribute("data-default-text")
        c.removeAttribute("data-default-text")
        c.classList.remove("has-search-marks")
    })
    if (search_box.value != "") {
        Array.from(document.getElementById("files-list").children).forEach((c) => {
            var match = c.getAttribute("data-filename").match(new RegExp(search_box.value, "i"))
            if (match) {
                var p = c.querySelector("p")
                if (!p.classList.contains("has-search-marks")) {
                    p.classList.add("has-search-marks")
                    p.setAttribute("data-default-text", p.innerHTML)
                }

                p.innerHTML = c.querySelector("p").innerHTML.replace(new RegExp(search_box.value, "gi"), (term, pos) => `<mark class="search-mark">${term}</mark>`)
            }
        })
        var first_search_mark = document.querySelector(".search-mark")
        if (first_search_mark) {
            first_search_mark.classList.add("search-mark-selected")
            setTimeout(() => first_search_mark.scrollIntoView({
                behavior: 'smooth',
                block: 'center',
                inline: 'start'
            }), 1)
            _search_update_selected()
        }
    }
}
var typingCoolTimeout
document.getElementById("search-box").addEventListener("input", (e) => {
	if(typingCoolTimeout){clearTimeout(typingCoolTimeout); typingCoolTimeout = undefined}
	// typingCoolTimeout = setTimeout(_search_process, 250)
	typingCoolTimeout = setTimeout(_search_process, 0)
})

var _search_update_selected = () => {
    var selected_search_mark = document.querySelector(".search-mark.search-mark-selected")
    if (selected_search_mark) {
        select(selected_search_mark.closest("li").getAttribute("data-filename"))
    }
}
document.getElementById("search-box").addEventListener("keydown", (event) => {
    if (event.code == "Enter") {
        var direction = event.shiftKey ? -1 : 1
        var search_marks = Array.from(document.querySelectorAll(".search-mark"))
        var selected_search_mark = document.querySelector(".search-mark.search-mark-selected")
        if (selected_search_mark) {
            selected_search_mark.classList.remove("search-mark-selected")
            var new_index = search_marks.indexOf(selected_search_mark) + direction
            if (new_index > (search_marks.length - 1)) {
                new_index = 0
            }
            if (new_index < 0) {
                new_index = (search_marks.length - 1)
            }
            search_marks[new_index].classList.add("search-mark-selected")
            search_marks[new_index].scrollIntoView({
                behavior: 'smooth',
                block: 'center',
                inline: 'start'
            })
            _search_update_selected()
        }
    }
})
window.onblur = () => document.activeElement.blur()
document.addEventListener("keydown", main_document_onkeypress);