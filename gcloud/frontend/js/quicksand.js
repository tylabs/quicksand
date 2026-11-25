/*
 * QuickSand Frontend JavaScript
 * Copyright (c) 2024-2026 Tyler McLellan / @tylabs
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
		var oReq = new XMLHttpRequest();
		var url = CONFIG.MITRE_JSON_PATH;
		oReq.open("GET", url, false);
		oReq.overrideMimeType("application/json");
		oReq.send();
		if (oReq.status == 200) {
			try {
				attackjson = JSON.parse(oReq.responseText);
			} catch (e) {
				attackjson = {};
			}
		}
	}

	if (attackjson != null && Object.prototype.hasOwnProperty.call(attackjson, technique)) {
		return attackjson[technique];
	}
	return null;
}

function baseName(base) {
	return String(base || "").split(/[\\/]/).pop();
}

function escapeHtml(val) {
	return String(val == null ? "" : val)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;")
		.replace(/`/g, "&#96;");
}

function safeHref(url) {
	var raw = String(url == null ? "" : url).trim();
	if (/^(?:javascript|data|vbscript):/i.test(raw)) {
		return "#";
	}
	return escapeHtml(raw);
}

function doReport(r) {
	if (!r || typeof r !== "object") {
		return "<p>Invalid report payload</p>";
	}
	var out = "<H3>Metadata</H3>";
	out += "<p>";
	if (typeof r['filename'] != "undefined" && r['filename'] !== null) {
		out += "filename:&nbsp;" + escapeHtml(baseName(r['filename'])) + "<br>";
	}
	out += "type:&nbsp;" + escapeHtml(r['type']) + "<br>";
	out += "md5:&nbsp;" + escapeHtml(r['md5']) + "<br>";
	out += "sha1:&nbsp;" + escapeHtml(r['sha1']) + "<br>";
	out += "sha256:&nbsp;" + escapeHtml(r['sha256']) + "<br>";
	out += "size:&nbsp;" + escapeHtml(r['size']);
	if (typeof r['cart'] == "object" && r['cart'] !== null) {
		if (typeof r['cart']['name'] == "string" && r['cart']['name'] !== "") {
			out += "<br>cart_name:&nbsp;" + escapeHtml(baseName(r['cart']['name']));
		}
		if (typeof r['cart']['payload_sha256'] == "string") {
			out += "<br>payload_sha256:&nbsp;" + escapeHtml(r['cart']['payload_sha256']);
		}
	}
	out += "</P>";
	out += "<p>started:&nbsp;" + escapeHtml(r['started']) + "<br>";
	out += "finished:&nbsp;" + escapeHtml(r['finished']) + "<br>";
	out += "elapsed:&nbsp;" + escapeHtml(r['elapsed']) + "<br>";
	out += "version:&nbsp;" + escapeHtml(r['version']) + "</P>";

	if (typeof r['structhash'] != "undefined") {
		out += "<H3>Similarity</H3>";
		out += "<p>structhash:&nbsp;" + escapeHtml(r['structhash']) + "<br>";
		if (typeof r['struzzy'] != "undefined") {
			out += "struzzy:&nbsp;" + escapeHtml(r['structhash_elements']) + ":" + escapeHtml(r['struzzy']) + "<br>";
		}
		out += "</P>";
	}

	var safeRating = parseInt(r['rating'], 10);
	if (isNaN(safeRating)) {
		safeRating = 0;
	}
	var safeRisk = escapeHtml(r['risk']);
	out += "<H3>Result</H3>";
	out += "<canvas width=200 height=100 id=\"risk\"></canvas>";
	if (safeRating == 1) {
		out += "<p>risk:&nbsp;<font color=crimson>" + safeRisk + "</font><br>";
	} else if (safeRating == 2) {
		out += "<p>risk:&nbsp;<font color=red>" + safeRisk + "</font><br>";
	} else if (safeRating == 3) {
		out += "<p>risk:&nbsp;<font color=darkred>" + safeRisk + "</font><br>";
	} else {
		out += "<p>risk:&nbsp;<font color=limegreen>" + safeRisk + "</font><br>";
	}
	out += "score:&nbsp;" + escapeHtml(r['score']) + "</P>";

	out += "<input type=hidden id=\"rating\" name=\"rating\" value=\"" + safeRating + "\">";

	if (typeof r['results'] === "object" && r['results'] !== null) {
		for (var name in r['results']) {
			if (!Object.prototype.hasOwnProperty.call(r['results'], name)) continue;
			out += "<h4>@" + escapeHtml(name) + ":</H4>";
			var streamHits = r['results'][name];
			if (!streamHits || typeof streamHits !== "object") continue;
			for (var i in streamHits) {
				if (!Object.prototype.hasOwnProperty.call(streamHits, i)) continue;
				var hit = streamHits[i] || {};
				out += "<P>Yara rule:<b>&nbsp;" + escapeHtml(hit["rule"]) + "</b>";
				if (typeof hit["type"] != "undefined" && hit["type"] !== null && hit["type"] !== "") {
					out += "&nbsp;(" + escapeHtml(hit["type"]) + ")";
				}
				out += "<BR>";
				out += "Description:&nbsp;<B>" + escapeHtml(hit["desc"]) + "</b><BR>";

				if (typeof hit["mitre"] != "undefined" && hit["mitre"] !== null && String(hit["mitre"]).trim() !== "") {
					var mitre = String(hit["mitre"]).split(/\s+/);
					out += "Mitre Att&amp;ck Technique:";
					for (var attack = 0; attack < mitre.length; attack++) {
						var techId = mitre[attack];
						if (!techId) continue;
						var technique = getAttack(techId);
						if (technique != null) {
							out += "&nbsp;<span class=\"mitre\" title=\"" + escapeHtml(technique) + "\">" + escapeHtml(techId) + "</span> ";
						} else {
							out += "&nbsp;<span class=\"mitre\">" + escapeHtml(techId) + " </span>";
						}
					}
				}
				out += "</p>";

				if (typeof hit["strings"] != "undefined" && hit["strings"] !== null) {
					out += "<ul>";
					if (Array.isArray(hit["strings"])) {
						for (var sIdx = 0; sIdx < hit["strings"].length; sIdx++) {
							var sTuple = hit["strings"][sIdx] || [];
							out += "<li>@" + escapeHtml(sTuple[0]) + ": <small>" + escapeHtml(sTuple[2]) + "</small></li>";
						}
					} else {
						var stringsArray = String(hit["strings"]).split("\n");
						for (var j = 0; j < stringsArray.length; j++) {
							var line = stringsArray[j].trim();
							if (line) {
								var parts = line.split("at offset");
								if (parts.length >= 2) {
									var identifier = parts[0].trim();
									var restParts = parts[1].split(":");
									if (restParts.length >= 2) {
										var offsetVal = restParts[0].trim();
										var data = restParts.slice(1).join(":").trim();
										out += "<li>@" + escapeHtml(identifier) + " (" + escapeHtml(offsetVal) + "): <small>" + escapeHtml(data) + "</small></li>";
									} else {
										out += "<li>" + escapeHtml(line) + "</li>";
									}
								} else {
									out += "<li>" + escapeHtml(line) + "</li>";
								}
							}
						}
					}
					out += "</ul>";
				}
			}
		}
	}

	var lookupHash = String(r['sha256'] || r['sha512'] || "");
	var searchHref = safeHref(API_ENDPOINTS.SEARCH + "?query=" + encodeURIComponent(lookupHash));
	out += "<P><small><a target=\"_blank\" rel=\"noopener noreferrer\" href=\"" + searchHref + "\">json</a> | <a target=\"_blank\" rel=\"noopener noreferrer\" href=\"" + safeHref(CONFIG.HOWTO_URL) + "\">how to interpret these results</a></small></P>";

	return out;
}

function get(name) {
	try {
		if (typeof URLSearchParams !== "undefined") {
			var params = new URLSearchParams(window.location.search);
			var val = params.get(name);
			return val === null ? undefined : val;
		}
	} catch (e) {
		// Fall through to regex parser
	}
	try {
		var m = (new RegExp('[?&]' + encodeURIComponent(name) + '=([^&]*)')).exec(location.search);
		if (m) {
			return decodeURIComponent(m[1].replace(/\+/g, " "));
		}
	} catch (e) {
		return undefined;
	}
	return undefined;
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
		percentColors: [[0.0, "#a9d70b"], [0.50, "#f9c802"], [1.0, "#ff0000"]],
		staticZones: [
			{strokeStyle: "#30B32D", min: 0, max: 1.5},
			{strokeStyle: "#FFDD00", min: 1.5, max: 2.5},
			{strokeStyle: "#FF8C00", min: 2.5, max: 3.5},
			{strokeStyle: "#F03E3E", min: 3.5, max: 5}
		],
		strokeColor: '#E0E0E0',
		generateGradient: true
	};
	var target = document.getElementById('risk');
	if (!target || typeof Gauge === "undefined") return;
	var gauge = new Gauge(target).setOptions(opts);
	gauge.maxValue = 5;
	gauge.animationSpeed = 32;
	var score = (parseInt(risk, 10) || 0) + 1;
	gauge.set(score);
}

function process() {
	var rawUuid = String(get('uuid') || "").trim();
	var safeUuid = escapeHtml(rawUuid);
	document.getElementById("text").innerHTML = "<font color=orange>Processing.... Task ID: " + safeUuid + "</font>";

	var oReq = new XMLHttpRequest();
	oReq.onreadystatechange = function() {
		if (this.readyState == 4) {
			if (this.status == 200) {
				document.getElementById("text").innerHTML = "<font color=red>Complete.... Task ID: " + safeUuid + "</font>";
				var myArr = JSON.parse(this.responseText);
				document.getElementById("qsreport").innerHTML = doReport(myArr);
				speed(document.getElementById("rating").value);
			} else if (this.status == 504 || this.status == 500) {
				document.getElementById("text").innerHTML = "<font color=red>Exceeded Time.... Task ID: " + safeUuid + "</font>";
			} else {
				document.getElementById("text").innerHTML = "<font color=red>Analysis Error (" + escapeHtml(this.status) + ").... Task ID: " + safeUuid + "</font>";
			}
		}
	};
	var url = API_ENDPOINTS.ANALYZE + "?uuid=" + encodeURIComponent(rawUuid);
	if (typeof get('rerun') != "undefined" && get('rerun') == "1") {
		url += "&rerun=1";
	}
	if (typeof get('password') != "undefined" && get('password') !== "") {
		url += "&password=" + encodeURIComponent(get('password'));
	}
	oReq.open("GET", url);
	oReq.send();
}

function search() {
	var rawHash = String(get('query') || "").trim();
	var safeHash = escapeHtml(rawHash);
	if (rawHash != "") {
		document.getElementById("text").innerHTML = "<font color=orange>Searching.... Query: " + safeHash + "</font>";

		var oReq = new XMLHttpRequest();
		oReq.onreadystatechange = function() {
			if (this.readyState == 4) {
				if (this.status == 200) {
					var myArr = JSON.parse(this.responseText);
					if (typeof myArr['error'] != "undefined") {
						document.getElementById("text").innerHTML = "<font color=red>Not Found.... Query: " + safeHash + "</font>";
					} else {
						document.getElementById("text").innerHTML = "<font color=red>Found.... Query: " + safeHash + "</font>";
						document.getElementById("qsreport").innerHTML = doReport(myArr);
						speed(document.getElementById("rating").value);
					}
				} else if (this.status == 404 || this.status == 400) {
					document.getElementById("text").innerHTML = "<font color=red>Not Found.... Query: " + safeHash + "</font>";
				} else if (this.status == 500 || this.status == 504) {
					document.getElementById("text").innerHTML = "<font color=red>Exceeded Time.... Query: " + safeHash + "</font>";
				} else {
					document.getElementById("text").innerHTML = "<font color=red>Search Error (" + escapeHtml(this.status) + ").... Query: " + safeHash + "</font>";
				}
			}
		};

		oReq.open("GET", API_ENDPOINTS.SEARCH + "?query=" + encodeURIComponent(rawHash));
		oReq.send();
	}
}

function reqListener() {
	console.log(this.responseText);
}

function getSignature() {
	var filelist = document.getElementById('file');
	var file = filelist.files[0];

	if (!file) {
		document.getElementById("qserror").innerHTML = "<font color=red>Please select a file to analyze</font>";
		return false;
	}

	if (file.size > CONFIG.MAX_FILE_SIZE) {
		document.getElementById("qserror").innerHTML = "<font color=red>File over 20MB Size: " + escapeHtml(file.size) + "</font>";
		return false;
	}

	document.getElementById("qserror").innerHTML = "<font color=orange>Getting upload URL...</font>";

	var oReq = new XMLHttpRequest();
	oReq.onreadystatechange = function() {
		if (this.readyState == 4 && this.status == 200) {
			try {
				var response = JSON.parse(this.responseText);
				if (response.upload_url && response.meta) {
					document.getElementById("qserror").innerHTML = "<font color=orange>Uploading file...</font>";

					var uploadReq = new XMLHttpRequest();
					uploadReq.open("PUT", response.upload_url);

					uploadReq.setRequestHeader("x-goog-meta-ip", String(response.meta.submitter_ip || "unknown"));
					uploadReq.setRequestHeader("x-goog-meta-original-filename", String(response.meta.original_filename || "unknown"));
					if (response.meta.content_length_range) {
						uploadReq.setRequestHeader("x-goog-content-length-range", String(response.meta.content_length_range));
					}

					uploadReq.onreadystatechange = function() {
						if (this.readyState == 4) {
							if (this.status === 200 || this.status === 201) {
								document.getElementById("qserror").innerHTML = "<font color=green>Upload successful! Redirecting to analysis...</font>";
								var uuid = response.meta.uuid;
								if (!uuid || !/^[A-Za-z0-9._-]+$/.test(String(uuid))) {
									document.getElementById("qserror").innerHTML = "<font color=red>Error: No analysis ID received</font>";
									return;
								}
								window.location.href = CONFIG.REPORT_URL + "?uuid=" + encodeURIComponent(String(uuid));
							} else {
								document.getElementById("qserror").innerHTML = "<font color=red>Upload failed: " + escapeHtml(this.status) + "</font>";
							}
						}
					};

					uploadReq.onerror = function() {
						document.getElementById("qserror").innerHTML = "<font color=red>Upload failed: Network error</font>";
					};

					uploadReq.send(file);
				} else {
					document.getElementById("qserror").innerHTML = "<font color=red>Failed to get upload URL</font>";
				}
			} catch (e) {
				document.getElementById("qserror").innerHTML = "<font color=red>Error processing server response: " + escapeHtml(e.message) + "</font>";
			}
		} else if (this.readyState == 4) {
			document.getElementById("qserror").innerHTML = "<font color=red>Failed to get signature: " + escapeHtml(this.status) + "</font>";
		}
	};

	oReq.onerror = function() {
		document.getElementById("qserror").innerHTML = "<font color=red>Failed to get signature: Network error</font>";
	};

	oReq.open("GET", API_ENDPOINTS.UPLOAD + "?filename=" + encodeURIComponent(file.name));
	oReq.send();

	return false;
}

function pollAnalysisResults(url) {
	var pollInterval = 2000;
	var maxAttempts = 30;
	var attempts = 0;

	function checkResults() {
		attempts++;
		var xhr = new XMLHttpRequest();
		xhr.onreadystatechange = function() {
			if (this.readyState == 4) {
				if (this.status === 200) {
					try {
						var results = JSON.parse(this.responseText);
						if (results.error) {
							if (results.error === "exception" || results.error === "timeout") {
								document.getElementById("qserror").innerHTML = "<font color=red>Analysis failed: " + escapeHtml(results.message) + "</font>";
								return;
							}
							if (attempts < maxAttempts) {
								setTimeout(checkResults, pollInterval);
							} else {
								document.getElementById("qserror").innerHTML = "<font color=red>Analysis timed out</font>";
							}
						} else {
							document.getElementById("qserror").innerHTML = "<font color=green>Analysis complete!</font>";
							document.getElementById("qsreport").innerHTML = doReport(results);
							speed(document.getElementById("rating").value);
						}
					} catch (e) {
						document.getElementById("qserror").innerHTML = "<font color=red>Error processing results: " + escapeHtml(e.message) + "</font>";
					}
				} else if (this.status === 504) {
					document.getElementById("qserror").innerHTML = "<font color=red>Analysis timed out</font>";
				} else if (this.status === 500) {
					if (attempts < maxAttempts) {
						setTimeout(checkResults, pollInterval);
					} else {
						document.getElementById("qserror").innerHTML = "<font color=red>Analysis timed out</font>";
					}
				} else {
					document.getElementById("qserror").innerHTML = "<font color=red>Analysis failed: " + escapeHtml(this.status) + "</font>";
				}
			}
		};

		xhr.onerror = function() {
			if (attempts < maxAttempts) {
				setTimeout(checkResults, pollInterval);
			} else {
				document.getElementById("qserror").innerHTML = "<font color=red>Analysis failed: Network error</font>";
			}
		};

		xhr.open("GET", url);
		xhr.send();
	}

	checkResults();
}

function doForm(r) {
	var form = document.getElementById('quicksand');
	if (!form || !r || typeof r['fields'] !== 'object' || r['fields'] === null) return;
	for (var name in r['fields']) {
		if (!Object.prototype.hasOwnProperty.call(r['fields'], name)) continue;
		var input = document.createElement('input');
		input.setAttribute('name', String(name));
		input.setAttribute('value', String(r['fields'][name]));
		input.setAttribute('type', 'hidden');
		form.insertBefore(input, form[0]);
	}
}

function doSend() {
	return getSignature();
}
