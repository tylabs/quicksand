# QuickSand Lambda Function

For the Lambda web-based file analysis version of QuickSand, the following components are included.


## Builder Tools

Dockerfile: Generate a zip of the needed libraries for Python-Yara and other packages QuickSand needs.

```bash
docker build -t quicksand .
docker run -d quicksand
<docker_id is output here>
docker cp <docker_id>:/quicksand/dependencies.zip .
```

wait.py: Simple python script that the Dockerfile runs to keep the Docker image running to allow access to copy out the dependencies.zip.


## Lambda functions

functions/signurl.py: Sign a file upload url for a public file upload.

functions/lambda_function.py: Receive a file uuid and process it, cache and return json.

functions/search.py: Search for a file by MD5 hash

functions/config.py: S3 region and bucket name config for lambda_function.py, signurl.py and search.py


## Helper HTML and JS

html_js/default.html: File upload form, Javascript includes for template.

html_js/js/quicksand.js: JS files to render reports. Some urls in quicksand.js will need to be set.

html_js/report.md: Report page skeleton.

html_js/json/mitre.json: MITRE Attack reference.


## File Upload and Processing Overview

A web page with a file upload form triggers the creation of a signed upload url from the signurl.py function.

```html

<form id="quicksand" action="https://qsupload.s3.amazonaws.com/" method="post" enctype="multipart/form-data" onsubmit="return doSend();" >
<input id="file" name="file" type="file"><div id="qserror"></div>
<BR>
<input name="submit" value="Scan Document or PDF" type="submit" class="scan"  />
</form>

```

Then the user uploads the file to S3 directly using the signed url. The signed url has a redirect that includes a random uuid that will be used to trigger the file processing by the lambda_function.py function. Json is returned and rendered by Javascript on a report page (example [report.md](html_js/report.md).

Optional search.py function to search for a cached report by md5. For a more complete experience, you may with to store and index the json results and create a full featured search and reporting capability. For demo purposes on [scan.tylabs.com](https://scan.tylabs.com/) we don't index the reporting and expire/delete S3 files to save storage costs.

