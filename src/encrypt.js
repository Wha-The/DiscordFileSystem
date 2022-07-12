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

var reflect_aes_key = function(aes){
	var set = () => {
		CookieManager.setCookie('ssl_client_aes_key', aes)
	}
	if(window.CookieManager)set()
	else Scripts.runAfterLoaded("CookieManager", set)
}

var init = function(){
	var shared_aes_key = ((window.crypto.randomUUID&&window.crypto.randomUUID())||(() => {
	  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
	    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
	  );
	})()).replace(/-/g, "")
	$.post("/rsa_generate", function(response){
		server_key_pair = new JSEncrypt()
		server_key_pair.setPublicKey(response.key)
		reflect_aes_key(server_key_pair.encrypt(shared_aes_key))
		window.ENCRYPTION_READY = 1
	})

	var generateNonce = function(){
		return Math.floor(Math.random() * (1e8 - 1e7 + 1) + 1e7)
	}

	window.client_encrypt = function(data){ // recipient = server
		return CryptoJS.AES.encrypt(data + generateNonce(), CryptoJS.SHA256(shared_aes_key), {mode: CryptoJS.mode.ECB}).toString();
	}
	window.client_decrypt = function(data){ // recipient = client
		return CryptoJS.AES.decrypt(data, CryptoJS.SHA256(shared_aes_key), {mode: CryptoJS.mode.ECB}).toString(CryptoJS.enc.Utf8).slice(null, -8);
	}

	window.addEventListener("beforeunload", function(e){
		CookieManager.setCookie("ssl_client_aes_key", "")
		CookieManager.setCookie("ssl_server_private_key", "")
	}, false)
}
dynamicallyLoadScript(`https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js`, function(){
	if(window.JSEncrypt)init()
	else Scripts.runAfterLoaded("rsa", init)
})
