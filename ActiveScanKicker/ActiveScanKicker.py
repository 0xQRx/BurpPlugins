from burp import IBurpExtender, ITab
from java.awt import BorderLayout
from java.net import URL
from javax.swing import JButton, JPanel, JScrollPane, JTextArea, SwingUtilities

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ActiveScan Kicker")
        SwingUtilities.invokeLater(self.createUI)
        return

    def createUI(self):
        self._panel = JPanel(BorderLayout())
        self._urlTextArea = JTextArea(20, 50)
        self._scanButton = JButton("Scan URLs", actionPerformed=self.startScan)
        self._panel.add(JScrollPane(self._urlTextArea), BorderLayout.CENTER)
        self._panel.add(self._scanButton, BorderLayout.SOUTH)
        self._callbacks.addSuiteTab(self)
        return

    def getTabCaption(self):
        return "ActiveScan Kicker"

    def getUiComponent(self):
        return self._panel

    def startScan(self, event):
        urls = self._urlTextArea.getText().split("\n")
        for url in urls:
            url = url.strip()
            if not url:
                continue
            try:
                parsed_url = URL(url)
                host = parsed_url.getHost()
                port = parsed_url.getPort()
                protocol = parsed_url.getProtocol().lower()
                
                # Set default ports if not specified
                if port == -1:
                    port = 443 if protocol == "https" else 80
                
                http_service = self._helpers.buildHttpService(host, port, protocol == "https")
                
                # Build request path with query parameters
                path = parsed_url.getPath() or "/"
                query = parsed_url.getQuery()
                full_path = "{}?{}".format(path, query) if query else path
                
                # Build valid HTTP request
                headers = [
                    "GET {} HTTP/1.1".format(full_path),
                    "Host: {}".format(host),
                    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language: en-US,en;q=0.5",
                    "Accept-Encoding: gzip, deflate, br",
                    "Upgrade-Insecure-Requests: 1",
                    "Sec-Fetch-Dest: document",
                    "Sec-Fetch-Mode: navigate",
                    "Sec-Fetch-Site: none",
                    "Sec-Fetch-User: ?1",
                    "Priority: u=0, i",
                    "Te: trailers"
                ]
                
                # Create request bytes using buildHttpMessage
                request_bytes = self._helpers.buildHttpMessage(headers, None)
                
                # Submit to active scanner
                self._callbacks.doActiveScan(
                    http_service.getHost(),
                    http_service.getPort(),
                    http_service.getProtocol() == "https",
                    request_bytes,
                    None
                )
                
                self._callbacks.printOutput("Queued for scanning: {}".format(url))
                
            except Exception as e:
                self._callbacks.printError("Error scanning {}: {}".format(url, str(e)))
        
        self._callbacks.printOutput("Scanning initiated for {} URLs".format(len(urls)))