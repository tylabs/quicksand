# QuickSand for Google Cloud Run Functions

- function/gcp_combined.py: Function code

- function/requirements.txt: Python requirements

- function/env.txt: Suggest environment variables

- frontend/index.html: Simple file upload implementation

- frontend/report.html: Simple report page implementation

- frontend/search.html: Simple search for report by hash

- frontend/js/quicksand.js: Javascript

- frontend/js/gauge.min.js: Report speedometer code


## Cloud Storage Bucket

A single bucket is required, private access only, to store files and reports (/new for files, /report for reports).


## Google Cloud Run Functions

- /upload -> File signing service

- /analyze -> Analysis service

- /search -> Search service



## Function Entry Point

Cloud Run -> Write a Function -> Inline Editor
Python 3.13

- See env.txt for required environment variables.

- Security: Assign your new service principal, not the default.

- Main handler function quicksand_combined




## Separate handler functions for each service:

- handle_upload() - Handles file upload signing

- handle_analyze() - Handles file analysis

- handle_search() - Handles searching for reports



# GCP Permissions

Create a new service account with the roles:

- Storage Object Admin role (this could be limited more granularly to creating, viewing objects in the selected bucket).

- Service Account Token Creator role (for signing blobs upload urls).



## CORS Config for the Bucket

CORS configuration is required to accept the asynchronous connections from a web browser.


Create this cors.json:

```
[
  {
    "origin": [
      "https://<website hosting front end>",
      "https://*.<website hosting front end>"
    ],
    "method": ["GET", "PUT", "POST", "DELETE", "OPTIONS"],
    "responseHeader": ["*"]
    "maxAgeSeconds": 3600
  }
]
```
or more detailed settings:

```
[
  {
    "origin": [
      "https://<website hosting front end>",
      "https://*.<website hosting front end>"
    ],
    "method": ["GET", "PUT", "POST", "DELETE", "OPTIONS"],
    "responseHeader": [
      "x-goog-meta-ip",
      "x-goog-meta-original-filename",
      "Content-Type",
      "Content-Length",
      "ETag",
      "x-goog-generation",
      "x-goog-metageneration"
  ],
    "maxAgeSeconds": 3600
  }
]
```
GCP Console run:
`gsutil cors set cors.json gs://<bucket_name>`


## Option Assign Custom Domain

- Cloud Run -> Manage custom domains