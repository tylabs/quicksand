/*
 * QuickSand Frontend JavaScript
 * Copyright (c) 2024 Tyler McLellan / @tylabs
 * Website: https://tylabs.com
 */

// Configuration variables - Loaded from environment variables
const CONFIG = {
	API_BASE_URL: window.QUICKSAND_API_BASE_URL || 'https://api.tylabs.com',
	SCAN_BASE_URL: window.QUICKSAND_SCAN_BASE_URL || 'https://scan.tylabs.com',
	HOWTO_URL: 'howto',
	REPORT_URL: 'report',
	MAX_FILE_SIZE: 20971520, // 20MB in bytes
	MITRE_JSON_PATH: './assets/json/mitre.json'
};

// API endpoints
const API_ENDPOINTS = {
	UPLOAD: `${CONFIG.API_BASE_URL}/upload`,
	ANALYZE: `${CONFIG.API_BASE_URL}/analyze`,
	SEARCH: `${CONFIG.API_BASE_URL}/search`
};

var attackjson = null;

function getAttack(technique) {
	if (attackjson == null) {
		console.log("get json");
		var oReq = new XMLHttpRequest();

		var url = CONFIG.MITRE_JSON_PATH;
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
	var out = "<H3>Metadata</H3>";
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
				// Check if strings is an array (old format) or a string (new format)
				if (Array.isArray(r['results'][name][i]["strings"])) {
					// Old format handling - strings is an array of arrays
					for (var string in r['results'][name][i]["strings"]) {
						out += "<li>@" + r['results'][name][i]["strings"][string][0] + ": <small>" + r['results'][name][i]["strings"][string][2] + "</small></li>";
					}
				} else {
					// New format handling - strings is a string with newline-separated entries
					var stringsArray = r['results'][name][i]["strings"].split("\n");
					for (var j = 0; j < stringsArray.length; j++) {
						var line = stringsArray[j].trim();
						if (line) {
							// Parse the line which should be in format "identifier at offset X: data"
							var parts = line.split("at offset");
							if (parts.length >= 2) {
								var identifier = parts[0].trim();
								var restParts = parts[1].split(":");
								if (restParts.length >= 2) {
									var offset = restParts[0].trim();
									var data = restParts.slice(1).join(":").trim();
									out += "<li>@" + identifier + ": <small>" + data + "</small></li>";
								} else {
									out += "<li>" + line + "</li>";
								}
							} else {
								out += "<li>" + line + "</li>";
							}
						}
					}
				}
				out += "</ul>";
			}
		}

	}

	out += "<P><small><a target=\"_blank\" href=\"" + API_ENDPOINTS.SEARCH + "?query=" + r['md5'] + "\">json</a> | <a target=\"_blank\" href=\"" + CONFIG.HOWTO_URL + "\">how to interpret these results</a></small></P>";

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
	var url = API_ENDPOINTS.ANALYZE + "?uuid=" + uuid;
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


		oReq.open("GET", API_ENDPOINTS.SEARCH + "?query=" + hash);
		oReq.send();
	}
}



function reqListener () {
  console.log(this.responseText);
}

function getSignature() {
	var filelist = document.getElementById('file');
	var file = filelist.files[0];
	
	if (!file) {
		console.log("No file selected");
		document.getElementById("qserror").innerHTML = "<font color=red>Please select a file to analyze</font>";
		return false;
	}
	
	console.log("File selected:", {
		name: file.name,
		size: file.size,
		type: file.type
	});
	
	if (file.size > CONFIG.MAX_FILE_SIZE) {
		console.log("File too large:", file.size);
		document.getElementById("qserror").innerHTML = "<font color=red>File over 20MB Size: " + file.size + "</font>";
		return false;
	}

	// Show processing message
	document.getElementById("qserror").innerHTML = "<font color=orange>Getting upload URL...</font>";
	console.log("Requesting signed URL from:", API_ENDPOINTS.UPLOAD + "?filename=" + encodeURIComponent(file.name));

	var oReq = new XMLHttpRequest();
	oReq.onreadystatechange = function() {
		console.log("Signature request state:", this.readyState, "Status:", this.status);
		if (this.readyState == 4 && this.status == 200) {
			try {
				var response = JSON.parse(this.responseText);
				console.log("Received signed URL response:", response);
				
				if (response.upload_url) {
					// Show uploading message
					document.getElementById("qserror").innerHTML = "<font color=orange>Uploading file...</font>";
					console.log("Preparing to upload file to:", response.upload_url);
					
					// Upload the file to the signed URL
					var uploadReq = new XMLHttpRequest();
					uploadReq.open("PUT", response.upload_url);
					
					// Add required headers
					console.log("Setting upload headers:", {
						"x-goog-meta-ip": response.meta.submitter_ip,
						"x-goog-meta-original-filename": response.meta.original_filename
					});
					
					uploadReq.setRequestHeader("x-goog-meta-ip", response.meta.submitter_ip);
					uploadReq.setRequestHeader("x-goog-meta-original-filename", response.meta.original_filename);
					
					uploadReq.onreadystatechange = function() {
						console.log("Upload request state:", this.readyState, "Status:", this.status);
						if (this.readyState == 4) {
							if (this.status === 200 || this.status === 201) {
								console.log("Upload successful, redirecting to report page...");
								// Show success message
								document.getElementById("qserror").innerHTML = "<font color=green>Upload successful! Redirecting to analysis...</font>";
								
								// Get the uuid from the meta object in the response
								var uuid = response.meta.uuid;
								if (!uuid) {
									console.error("No uuid in response meta:", response);
									document.getElementById("qserror").innerHTML = "<font color=red>Error: No analysis ID received</font>";
									return;
								}
								
								// Redirect to report.html with the uuid
								window.location.href = CONFIG.REPORT_URL + "?uuid=" + uuid;
							} else {
								console.error("Upload failed with status:", this.status);
								console.error("Response:", this.responseText);
								document.getElementById("qserror").innerHTML = "<font color=red>Upload failed: " + this.status + "</font>";
							}
						}
					};
					
					uploadReq.onerror = function(e) {
						console.error("Upload network error:", e);
						document.getElementById("qserror").innerHTML = "<font color=red>Upload failed: Network error</font>";
					};
					
					console.log("Starting file upload...");
					uploadReq.send(file);
				} else {
					console.error("No upload URL in response");
					document.getElementById("qserror").innerHTML = "<font color=red>Failed to get upload URL</font>";
				}
			} catch (e) {
				console.error("Error processing server response:", e);
				document.getElementById("qserror").innerHTML = "<font color=red>Error processing server response: " + e.message + "</font>";
			}
		} else if (this.readyState == 4) {
			console.error("Failed to get signature:", this.status);
			console.error("Response:", this.responseText);
			document.getElementById("qserror").innerHTML = "<font color=red>Failed to get signature: " + this.status + "</font>";
		}
	};

	oReq.onerror = function(e) {
		console.error("Signature request network error:", e);
		document.getElementById("qserror").innerHTML = "<font color=red>Failed to get signature: Network error</font>";
	};

	oReq.open("GET", API_ENDPOINTS.UPLOAD + "?filename=" + encodeURIComponent(file.name));
	console.log("Sending signature request...");
	oReq.send();
	
	return false; // Prevent form submission
}

// Function to poll for analysis results
function pollAnalysisResults(url) {
	var pollInterval = 2000; // Poll every 2 seconds
	var maxAttempts = 30; // Maximum number of attempts (1 minute total)
	var attempts = 0;
	
	function checkResults() {
		attempts++;
		console.log("Polling attempt", attempts, "of", maxAttempts);
		
		var xhr = new XMLHttpRequest();
		xhr.onreadystatechange = function() {
			if (this.readyState == 4) {
				if (this.status === 200) {
					try {
						var results = JSON.parse(this.responseText);
						if (results.error) {
							if (results.error === "exception") {
								document.getElementById("qserror").innerHTML = "<font color=red>Analysis failed: " + results.message + "</font>";
								return;
							}
							// If we get a "processing" error, continue polling
							if (attempts < maxAttempts) {
								setTimeout(checkResults, pollInterval);
							} else {
								document.getElementById("qserror").innerHTML = "<font color=red>Analysis timed out</font>";
							}
						} else {
							console.log("Analysis results received");
							document.getElementById("qserror").innerHTML = "<font color=green>Analysis complete!</font>";
							document.getElementById("qsreport").innerHTML = doReport(results);
							speed(document.getElementById("rating").value);
						}
					} catch (e) {
						console.error("Error parsing results:", e);
						document.getElementById("qserror").innerHTML = "<font color=red>Error processing results: " + e.message + "</font>";
					}
				} else if (this.status === 500) {
					// Server error, continue polling
					if (attempts < maxAttempts) {
						setTimeout(checkResults, pollInterval);
					} else {
						document.getElementById("qserror").innerHTML = "<font color=red>Analysis timed out</font>";
					}
				} else {
					console.error("Unexpected status:", this.status);
					document.getElementById("qserror").innerHTML = "<font color=red>Analysis failed: " + this.status + "</font>";
				}
			}
		};
		
		xhr.onerror = function(e) {
			console.error("Poll request failed:", e);
			if (attempts < maxAttempts) {
				setTimeout(checkResults, pollInterval);
			} else {
				document.getElementById("qserror").innerHTML = "<font color=red>Analysis failed: Network error</font>";
			}
		};
		
		xhr.open("GET", url);
		xhr.send();
	}
	
	// Start polling
	checkResults();
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