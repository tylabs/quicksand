var attackjson = null;

function getAttack(technique) {
	if (attackjson == null) {
		var oReq = new XMLHttpRequest();
		var url = "https://scan.tylabs.com/assets/json/mitre.json";
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
	var out = "<H2>Metadata</H2>";
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
	var searchHref = safeHref("https://api.tylabs.com/put/search?query=" + encodeURIComponent(lookupHash));
	out += "<P><small><a target=\"_blank\" rel=\"noopener noreferrer\" href=\"" + searchHref + "\">json</a> | <a target=\"_blank\" rel=\"noopener noreferrer\" href=\"howto\">how to interpret these results</a></small></P>";

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
			} else if (this.status == 500 || this.status == 504) {
				document.getElementById("text").innerHTML = "<font color=red>Exceeded Time.... Task ID: " + safeUuid + "</font>";
			} else {
				document.getElementById("text").innerHTML = "<font color=red>Analysis Error (" + escapeHtml(this.status) + ").... Task ID: " + safeUuid + "</font>";
			}
		}
	};
	var url = "https://api.tylabs.com/put/gravel?rerun=1&uuid=" + encodeURIComponent(rawUuid);
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

		oReq.open("GET", "https://api.tylabs.com/put/search?query=" + encodeURIComponent(rawHash));
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
	if (file.size > 25000000) {
		document.getElementById("qserror").innerHTML = "<font color=red>File over 25MB Size: " + escapeHtml(file.size) + "</font>";
		return false;
	}

	var fullPath = document.getElementById('file').value;
	if (fullPath.length == 0) return false;

	var oReq = new XMLHttpRequest();
	oReq.open("GET", "https://api.tylabs.com/put/upload?filename=" + encodeURIComponent(fullPath), false);
	oReq.send();
	if (oReq.status == 200) {
		var myArr = JSON.parse(oReq.responseText);
		doForm(myArr);
		return true;
	}
	return false;
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
