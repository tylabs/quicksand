
var attackjson = null;

function getAttack(technique) {
	if (attackjson == null) {
		console.log("get json");
		var oReq = new XMLHttpRequest();

		var url = "https://scan.tylabs.com/assets/json/mitre.json";
		oReq.open("GET", url, false);
		oReq.overrideMimeType("application/json");
		oReq.send();
		if (oReq.status == 200) {
			attackjson = JSON.parse(oReq.responseText);
		} else {
			console.log(oReq.response);
		}
	
	}

	if (attackjson != null) {
		console.log("check");
		console.log(technique);
		return attackjson[technique];
	}
	return null;
}


function baseName(base)
{
	return base.split(/[\\/]/).pop();
}


function doReport(r) {
	var out = "<H2>Metadata</H2>";
	out += "<p>";
	if (typeof r['filename'] != "undefined") {
		out += "filename:&nbsp;" + baseName(r['filename'].replace(/(<([^>]+)>)/ig,"")) + "<br>";

	}
	out += "type:&nbsp;" + r['type'] + "<br>";
	out += "md5:&nbsp;" + r['md5'] + "<br>";
	out += "sha1:&nbsp;" + r['sha1'] + "<br>";
	out += "sha256:&nbsp;" + r['sha256'] + "<br>";
	out += "size:&nbsp;" + r['size'] + "</P>";
	out += "<p>started:&nbsp;" + r['started'] + "<br>";
	out += "finished:&nbsp;" + r['finished'] + "<br>";
	out += "elapsed:&nbsp;" + r['elapsed'] + "<br>";
	out += "version:&nbsp;" + r['version'] + "</P>";


	if (typeof r['structhash'] != "undefined") {
		out += "<H3>Similarity</H3>";
		out += "<p>structhash:&nbsp;" + r['structhash'] + "<br>";
		//out += "structhash version:&nbsp;v" + r['structhash_version'] + "<br>";
		if (typeof r['struzzy'] != "undefined") {
			out += "struzzy:&nbsp;" + r['structhash_elements'] + ":" + r['struzzy'] + "<br>";

		}
		out += "</P>";
	}


	out += "<H3>Result</H3>";
	out += "<canvas width=200 height=100 id=\"risk\"></canvas>";
	if (r['rating'] == 1) {
		out += "<p>risk:&nbsp;<font color=crimson>" + r['risk'] + "</font><br>";
	} else if (r['rating'] == 2) {
		out += "<p>risk:&nbsp;<font color=red>" + r['risk'] + "</font><br>";
	} else if (r['rating'] == 3) {
		out += "<p>risk:&nbsp;<font color=darkred>" + r['risk'] + "</font><br>";
	} else {
		out += "<p>risk:&nbsp;<font color=limegreen>" + r['risk'] + "</font><br>";
	}
	out += "score:&nbsp;" + r['score'] + "</P>";

	out += "<input type=hidden id=\"rating\" name=\"rating\" value=\"" + r['rating'] + "\">";

	for (var name in r['results']) {
		out += "<h4>@" + name + ":</H4>";
		for (var i in r['results'][name]) {
			console.log(name);
			out += "<P>Yara rule:<b>&nbsp;" + r['results'][name][i]["rule"] + "</b><BR>";
			out += "Description:&nbsp;<B>" + r['results'][name][i]["desc"] + "</b><BR>";

			if (typeof r['results'][name][i]["mitre"] != "undefined") {
				var mitre = r['results'][name][i]["mitre"].split(" ");

				out += "Mitre Att&ck Technique:";
				for (var attack in mitre) {
					var technique = getAttack(mitre[attack]);
					if (technique != null) {
						out += "&nbsp;<span class=\"mitre\" title=\"" + technique + "\">" + mitre[attack] + "</span> ";
					} else {

						out += "&nbsp;<span class=\"mitre\">" + mitre[attack] + " </span>";
					}
				}
			}
			out += "</p>";

			if (typeof r['results'][name][i]["strings"] != "undefined") {
				out += "<ul>";
				for (var string in r['results'][name][i]["strings"]) {
					out += "<li>@" + r['results'][name][i]["strings"][string][0] + ": <small>" + r['results'][name][i]["strings"][string][2] + "</small></li>";

				}
				out += "</ul>";
			}
		}

	}

	out += "<P><small><a target=\"_blank\" href=\"https://api.tylabs.com/put/search?query=" + r['md5'] + "\">json</a> | <a target=\"_blank\" href=\"howto\">how to interpret these results</a></small></P>";

        return out;
}

function get(name){
   if(name=(new RegExp('[?&]'+encodeURIComponent(name)+'=([^&]*)')).exec(location.search))
      return decodeURIComponent(name[1]);
}

function speed(risk) {
   var opts = {
  	lines: 12,
  	angle: 0.15,
  	lineWidth: 0.44,
  	pointer: {
    	length: 0.5,
    	strokeWidth: 0.035,
    	color: '#000000'
  	},
  limitMax: 'false', 
  percentColors: [[0.0, "#a9d70b" ], [0.50, "#f9c802"], [1.0, "#ff0000"]],
  staticZones: [
   	{strokeStyle: "#30B32D", min: 0, max: 1.5}, // green
   	{strokeStyle: "#FFDD00", min: 1.5, max: 2.5}, // Yellow
   	{strokeStyle: "#FF8C00", min: 2.5, max: 3.5}, // Orange
   	{strokeStyle: "#F03E3E", min: 3.5, max: 5}  // Red
	],
  strokeColor: '#E0E0E0',
  generateGradient: true
  };
  var target = document.getElementById('risk');
  var gauge = new Gauge(target).setOptions(opts);
  gauge.maxValue = 5;
  gauge.animationSpeed = 32;
  var score = parseInt(risk, 10) + 1;
  console.log("the risk score on the speedometer is " + score);
  gauge.set(score);
}


function process() {
	var uuid = get('uuid').replace(/(<([^>]+)>)/ig,"");
	document.getElementById("text").innerHTML = "<font color=orange>Processing.... Task ID: " + uuid + "</font>";


	var oReq = new XMLHttpRequest();

	oReq.onreadystatechange = function() {
    	if (this.readyState == 4 && this.status == 200) {
		document.getElementById("text").innerHTML = "<font color=red>Complete.... Task ID: " + uuid + "</font>";
		var myArr = JSON.parse(this.responseText);
        	document.getElementById("qsreport").innerHTML = doReport(myArr);
		speed(document.getElementById("rating").value);
    	} else if (this.readyState == 4 && this.status == 500) {
		document.getElementById("text").innerHTML = "<font color=red>Exceeded Time.... Task ID: " + uuid + "</font>";
    	}
	};
	var url = "https://api.tylabs.com/put/gravel?rerun=1&uuid=" + uuid;
	if (typeof get('rerun') != "undefined" && get('rerun') == "1") {
		url += "&rerun=1";
	}
	oReq.open("GET", url);
	oReq.send();
}

function search() {
	var hash = get('query').replace(/(<([^>]+)>)/ig,"");
	console.log(hash);
	if (hash != "") {
		document.getElementById("text").innerHTML = "<font color=orange>Searching.... Query: " + hash + "</font>";


		var oReq = new XMLHttpRequest();

		oReq.onreadystatechange = function() {
    			if (this.readyState == 4 && this.status == 200) {
				var myArr = JSON.parse(this.responseText);
				if (typeof myArr['error'] != "undefined") {
					document.getElementById("text").innerHTML = "<font color=red>Not Found.... Query: " + hash + "</font>";

				} else {
					document.getElementById("text").innerHTML = "<font color=red>Found.... Query: " + hash + "</font>";
					document.getElementById("qsreport").innerHTML = doReport(myArr);
					speed(document.getElementById("rating").value);

				}
    			} else if (this.readyState == 4 && this.status == 500) {
				document.getElementById("text").innerHTML = "<font color=red>Exceeded Time.... Query: " + hash + "</font>";
    			}
		};


		oReq.open("GET", "https://api.tylabs.com/put/search?query=" + hash);
		oReq.send();
	}
}



function reqListener () {
  console.log(this.responseText);
}

function getSignature() {
	//oReq.timeout = 14000;
	//oReq.addEventListener("load", reqListener);

	//oReq.onreadystatechange = function() {
    	//if (this.readyState == 4 && this.status == 200) {
        //	var myArr = JSON.parse(this.responseText);
        //	doForm(myArr);
    	//}
	//};
	//get filename

	var filelist = document.getElementById('file');
	var file = filelist.files[0];
	console.log(file.size);
	if (file.size > 10000000) {
		document.getElementById("qserror").innerHTML = "<font color=red>File over 10MB Size: " + file.size + "</font>";

		return false;
	}

	var fullPath = document.getElementById('file').value;

	console.log(fullPath);
	if (fullPath.length == 0) return false;

	var oReq = new XMLHttpRequest();

	oReq.open("GET", "https://api.tylabs.com/put/upload?filename=" + encodeURIComponent(fullPath), false);
	oReq.send();
	if (oReq.status == 200) {
		var myArr = JSON.parse(oReq.responseText);
		doForm(myArr);
		return true;
	} else {
		console.log(oReq.response);
	}
	return false;
	//console.log(oReq.response);
	//r = JSON.parse(oReq.response);
	//var r = oReq.response;
	//var r = JSON.parse(oReq.responseText);
}

function doForm(r) {
	var form=document.getElementById('quicksand')
	console.log(r['fields']);
	for (var name in r['fields']) {
			console.log(name);
			var input = document.createElement('input');//prepare a new input DOM element
			input.setAttribute('name', name);//set the param name
			input.setAttribute('value', r['fields'][name]);//set the value
			input.setAttribute('type', 'hidden')//set the type, like "hidden" or other

			form.insertBefore(input, form[0]);//append the input to the form
	}
	console.log(form);
}

function doSend() {
	return getSignature();
}