/*
Discord File System
Copyright (C) 2022  NWhut

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

Scripts = {
    runAfterLoaded:function(name,fn){
        if(!this.loaded_connected_callbacks[name]){this.loaded_connected_callbacks[name]=[]}
        this.loaded_connected_callbacks[name].push(fn)
    },
    loaded_connected_callbacks:{},
}
require = function(src,finished){
    finish = () => $.get("/src/"+src,(data)=>{
        finished(src, data)
    })

    finish()
    
}

checkcode = (src,data) => {
    if(Scripts.loaded_connected_callbacks[src]){
        Scripts.loaded_connected_callbacks[src].forEach((fn)=>{
            fn(data)
        })
    }
}
addcss = (src,styles) => {
    var styleSheet = document.createElement("style")
    styleSheet.type = "text/css"
    styleSheet.innerText = styles
    document.head.appendChild(styleSheet)
}
function dynamicallyLoadScript(url, callback) {
    var script = document.createElement("script");  // create a script DOM node
    script.src = url;  // set its src to the provided URL

    if(callback){
        script.onreadystatechange = callback;
        script.onload = callback;
    }
    
    document.head.appendChild(script);  // add it to the end of the head section of the page (could change 'head' to 'body' to add it to the end of the body section instead)
}

require("main",checkcode)
require("CookieManager",checkcode)
require("rsa",checkcode)
require("encrypt",checkcode)
require("css",addcss)
