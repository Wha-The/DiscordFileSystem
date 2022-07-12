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

info_websocket = null;
Disconnected = false
addHtml = (html) => {
	var d = document.createElement("div");
	d.innerHTML = html;
	document.body.appendChild(d);
	return d
}
function waitUntil(f,after){
	i = setInterval(function(){
		if (f()){
			clearInterval(i)
			after()
		}
	},50)
}
function showsnack(text,timeout) {
  var x = document.getElementById("snackbar");
  x.className = "show";
  x.innerHTML = text||x.innerHTML
  close = function(){ x.className = x.className.replace("show", ""); }
  if(timeout!=false){
  	return setTimeout(close, timeout||3000);
  }
  return close
}
Disconnected = false
function reconnect_webpage(){
	i = setInterval(function(){
		$.get(window.location.pathname,function(data){
			clearInterval(i)
			window.location.replace(window.location.pathname+"?pjreload=1")
		})
		},2000)
	return i
}
infosocket = {
	connect:function(){
		try{
			info_websocket = new WebSocket("ws"+(window.location.protocol=="https:"&&"s"||"")+"://"+location.host+"/info_websocket")
		}
		catch(e){
			console.log(e)
			return false;
		}

		info_websocket.onmessage = function(response){
			data = JSON.parse(response.data)
			action = data.action
			if (action=="servershutdown"){
				Disconnected = true
				close = showsnack("Server was shutdown. Reconnecting...",false)
				reconnect_webpage()
			}
		}

		info_websocket.onclose = function(){
			if(!Disconnected){
				showsnack("Disconnected from the server, attempting to reconnect...",false)
				reconnect_webpage()
			}
		}

		return true;
	}

}
infosocket.connect()
addHtml(`
<div id="snackbar"></div>
	`)
if (window.location.search.indexOf("pjreload") > -1){
	showsnack("Connected")
	var refresh = window.location.protocol + "//" + window.location.host + window.location.pathname;    
	window.history.pushState({ path: refresh }, '', refresh);
}