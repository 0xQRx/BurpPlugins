# Repeater Logger and Saver Extension for Burp Suite

This Burp Suite extension allows you to save and load request/response pairs with sanitization. You can set a working directory, manage sanitization strings, and load multiple requests into new Repeater tabs.

## Features

- Save request/response pairs to a specified directory with sanitized content.
- Load multiple request/response pairs from files into new Repeater tabs.
- Manage sanitization strings through a custom tab.
- Automatically generate filenames with HTTP method, URL path, date-time, and request hash.

## Installation

1. Download the `extention.py` file from this repository.
2. Open Burp Suite and go to the Extender tab.
3. Click on the "Add" button in the Extensions tab.
4. In the "Extension Details" dialog, select "Python" as the extension type.
5. Click on the "Select file..." button and choose the downloaded `extention.py` file.
6. Click "Next" and then "Finish" to load the extension.

## Usage

### Setting the Working Directory

1. Go to the "Repeater Logger" tab in Burp Suite.
2. Click the "Set Directory" button to select the working directory where requests and responses will be saved.

### Saving Request/Response Pairs

1. In the Repeater tab, right-click on the request and select "Save Request/Response".
2. The request and response will be saved to a file in the specified working directory with a filename format of:

`<http_method><url_path><datetime>_<request_hash>.json`


### Loading Request/Response Pairs

1. In the Repeater tab, right-click and select "Load Request/Response from File".
2. Select one or more files to load. Each request will be loaded into a new Repeater tab.

### Managing Sanitization Strings

1. In the Repeater tab, right-click and select "Manage Sanitization Strings".
2. Add or remove key-value pairs for sanitization.
3. Click "Save" to save the sanitization strings to a file in the working directory.

## Example

### Saving a Request/Response

- Request: `POST /api/v1/test HTTP/1.1`
- Saved filename: `post_api_v1_test_12:30-06-06-2024_f1d2d2f924e986ac86fdf7b36c94bcdf32beec15.json`

### Loading Multiple Requests

- Select multiple JSON files from the file chooser dialog.
- Each request will be loaded into a new Repeater tab.

## Acknowledgements

- [PortSwigger's Burp Suite Extender API](https://portswigger.net/burp/extender/api/)
