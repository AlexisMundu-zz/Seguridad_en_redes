let docs_ul = document.getElementById('files');
let last_login_h = document.getElementById('last-login');

fetch('/files')
  .then(response => response.json())
  .then(data => displayDocs(data.files));



function displayDocs(files){

  for(file of files){
    let li = document.createElement("li");
    li.appendChild(document.createTextNode(file));
    docs_ul.appendChild(li);
  }
}

fetch('/lastLogin')
.then(response => response.json())
.then(data => last_login_h.textContent = data.log ? `Last Login: ${new Date(data.log.timestamp)}` : "")