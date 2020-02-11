function getUrlVars() {
    var vars = {};
    var parts = window.location.href.replace(/[?&]+([^=&]+)=([^&]*)/gi, function(m,key,value) {
        vars[key] = value;
    });
    return vars;
}

var converter = new showdown.Converter();

function populate() {
	console.log("Load page content from .md.");
	
	var title = getUrlVars()["title"];
	setPost(title);
}

// Load text once DOM has been loaded
document.addEventListener('DOMContentLoaded', function () {
   populate();
});


function setPost(language) {

	// Load text from .md, add to DOM
	Promise.all([
	  fetch("postaukset/" + language + '.md').then(x => x.text()),
	]).then(([markdown]) => {
	  html = converter.makeHtml(markdown);
	  document.getElementById("content").innerHTML = html;
	});

}
