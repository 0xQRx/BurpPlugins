import os
import json
import datetime
import hashlib
from burp import IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation, IHttpService
from java.io import PrintWriter
from javax.swing import JMenuItem, JFileChooser, JOptionPane, JPanel, JTable, JScrollPane, JButton, JDialog, JLabel
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, GridLayout

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Repeater Logger and Saver")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        
        # Register ourselves as a context menu factory
        callbacks.registerContextMenuFactory(self)
        
        # Add custom tab
        self.panel = JPanel(BorderLayout())
        self.directory_panel = JPanel(GridLayout(2, 1))
        self.directory_label = JLabel("Working Directory: Not Set")
        self.directory_button = JButton("Set Directory", actionPerformed=self.set_directory)
        self.directory_panel.add(self.directory_label)
        self.directory_panel.add(self.directory_button)
        self.panel.add(self.directory_panel, BorderLayout.NORTH)
        callbacks.addSuiteTab(self)
        
        # Load sanitization strings from file
        self.sanitization_file = None
        self.sanitization_strings = {}
        
        self.stdout.println("Repeater Logger and Saver extension loaded")

    def getTabCaption(self):
        return "Repeater Logger"

    def getUiComponent(self):
        return self.panel

    def set_directory(self, event):
        file_chooser = JFileChooser()
        file_chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        result = file_chooser.showOpenDialog(None)
        
        if result == JFileChooser.APPROVE_OPTION:
            self.data_dir = file_chooser.getSelectedFile().getAbsolutePath()
            self.directory_label.setText("Working Directory: {}".format(self.data_dir))
            self.ensure_data_directory()
            self.sanitization_file = os.path.join(self.data_dir, "sanitization.json")
            self.sanitization_strings = self.load_sanitization_strings()
            JOptionPane.showMessageDialog(None, "Directory set to {}".format(self.data_dir))
        else:
            JOptionPane.showMessageDialog(None, "No directory selected, using default directory.")
            self.data_dir = "/tmp"
            self.directory_label.setText("Working Directory: {}".format(self.data_dir))
            self.ensure_data_directory()
            self.sanitization_file = os.path.join(self.data_dir, "sanitization.json")
            self.sanitization_strings = self.load_sanitization_strings()
    
    def ensure_data_directory(self):
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
    
    def load_sanitization_strings(self):
        if self.sanitization_file and os.path.exists(self.sanitization_file):
            with open(self.sanitization_file, 'r') as f:
                return json.load(f)
        return {}

    def save_sanitization_strings(self):
        if self.sanitization_file:
            with open(self.sanitization_file, 'w') as f:
                json.dump(self.sanitization_strings, f, indent=4)
    
    def createMenuItems(self, invocation):
        menu = []
        if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            menu_item_save = JMenuItem("Save Request/Response", actionPerformed=lambda x: self.print_and_save_request_response(invocation))
            menu.append(menu_item_save)
            menu_item_load = JMenuItem("Load Request/Response from File", actionPerformed=lambda x: self.load_request_response(invocation))
            menu.append(menu_item_load)
            menu_item_sanitize = JMenuItem("Manage Sanitization Strings", actionPerformed=lambda x: self.manage_sanitization_strings())
            menu.append(menu_item_sanitize)
        return menu
    
    def manage_sanitization_strings(self):
        dialog = JDialog()
        dialog.setTitle("Manage Sanitization Strings")
        dialog.setSize(400, 300)
        dialog.setLayout(BorderLayout())
        
        # Table model for sanitization strings
        table_model = DefaultTableModel(["Key", "Value"], 0)
        
        # Load existing sanitization strings into the table model
        for key, value in self.sanitization_strings.items():
            table_model.addRow([key, value])
        
        table = JTable(table_model)
        scroll_pane = JScrollPane(table)
        
        # Panel for buttons
        button_panel = JPanel()
        
        button_add = JButton("Add")
        button_remove = JButton("Remove")
        button_save = JButton("Save")
        
        button_panel.add(button_add)
        button_panel.add(button_remove)
        button_panel.add(button_save)
        
        def add_row(event):
            table_model.addRow(["", ""])
        
        def remove_row(event):
            selected_row = table.getSelectedRow()
            if selected_row != -1:
                table_model.removeRow(selected_row)
        
        def save_sanitization_strings(event):
            new_sanitization_strings = {}
            for row in range(table_model.getRowCount()):
                key = table_model.getValueAt(row, 0)
                value = table_model.getValueAt(row, 1)
                if key and value:
                    new_sanitization_strings[key] = value
            self.sanitization_strings = new_sanitization_strings
            self.save_sanitization_strings()
            dialog.dispose()
            JOptionPane.showMessageDialog(None, "Sanitization strings saved.")
        
        button_add.addActionListener(add_row)
        button_remove.addActionListener(remove_row)
        button_save.addActionListener(save_sanitization_strings)
        
        dialog.add(scroll_pane, BorderLayout.CENTER)
        dialog.add(button_panel, BorderLayout.SOUTH)
        
        dialog.setModal(True)
        dialog.setVisible(True)

    def sanitize_content(self, content):
        if isinstance(content, (bytes, bytearray)):
            content = content.decode('utf-8')
        for key, value in self.sanitization_strings.items():
            content = content.replace(key, value)
        return content.encode('utf-8')

    def reverse_sanitize_content(self, content):
        if isinstance(content, (bytes, bytearray)):
            content = content.decode('utf-8')
        for key, value in self.sanitization_strings.items():
            content = content.replace(value, key)
        return content.encode('utf-8')
    
    def print_and_save_request_response(self, invocation):
        if not hasattr(self, 'data_dir') or not self.data_dir:
            JOptionPane.showMessageDialog(None, "Please set the working directory first.")
            return
        
        request_response = invocation.getSelectedMessages()[0]
        request = request_response.getRequest()
        response = request_response.getResponse()
        
        # Analyze request
        analyzed_request = self._helpers.analyzeRequest(request)
        request_headers = [str(header) for header in analyzed_request.getHeaders()]
        request_body = request[analyzed_request.getBodyOffset():].tostring()
        http_method = analyzed_request.getMethod()
        
        # Extract the first header to get the path
        first_header = request_headers[0]
        path = first_header.split(" ")[1].split("?")[0]
        url_path = path.replace("/", "_").strip("_")
        
        # Analyze response if it exists
        if response:
            analyzed_response = self._helpers.analyzeResponse(response)
            response_headers = [str(header) for header in analyzed_response.getHeaders()]
            response_body = response[analyzed_response.getBodyOffset():].tostring()
        else:
            response_headers = []
            response_body = "No response"
        
        # Sanitize request/response headers and body
        request_headers = [self.sanitize_content(header) for header in request_headers]
        request_body = self.sanitize_content(request_body)
        response_headers = [self.sanitize_content(header) for header in response_headers]
        response_body = self.sanitize_content(response_body)
        
        # Print request/response to the console
        self.stdout.println("Request:")
        for header in request_headers:
            self.stdout.println(header)
        self.stdout.println(request_body)
        
        self.stdout.println("\nResponse:")
        for header in response_headers:
            self.stdout.println(header)
        self.stdout.println(response_body)
        
        # Save request/response to a file
        data = {
            "request": {
                "headers": [header.decode('utf-8') if isinstance(header, bytes) else header for header in request_headers],
                "body": request_body.decode('utf-8') if isinstance(request_body, bytes) else request_body
            },
            "response": {
                "headers": [header.decode('utf-8') if isinstance(header, bytes) else header for header in response_headers],
                "body": response_body.decode('utf-8') if isinstance(response_body, bytes) else response_body
            }
        }
        
        # Generate hash for the request
        request_hash = hashlib.md5(json.dumps(data["request"], sort_keys=True).encode('utf-8')).hexdigest()
        
        # Generate filename
        current_time = datetime.datetime.now().strftime("%H:%M-%m-%d-%Y")
        file_name = "{}_{}_{}_{}.json".format(http_method.lower(), url_path, current_time, request_hash)
        file_path = os.path.join(self.data_dir, file_name)
        
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=4)
            self.stdout.println("Request/Response saved to file: {}".format(file_path))
        except Exception as e:
            self.stdout.println("Error saving request/response to file: {}".format(str(e)))

    def load_request_response(self, invocation):
        if not hasattr(self, 'data_dir') or not self.data_dir:
            JOptionPane.showMessageDialog(None, "Please set the working directory first.")
            return
        
        # Open a file chooser dialog to select the file to load
        file_chooser = JFileChooser(self.data_dir)
        file_chooser.setMultiSelectionEnabled(True)
        result = file_chooser.showOpenDialog(None)
        
        if result == JFileChooser.APPROVE_OPTION:
            files = file_chooser.getSelectedFiles()
            
            for file in files:
                file_path = file.getAbsolutePath()
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    
                    # Extract request and response data
                    request_headers = data['request']['headers']
                    request_body = data['request']['body'].encode('utf-8')
                    response_headers = data['response']['headers']
                    response_body = data['response']['body'].encode('utf-8')
                    
                    # Reverse sanitize request and response data
                    request_headers = [self.reverse_sanitize_content(header) for header in request_headers]
                    request_body = self.reverse_sanitize_content(request_body)
                    response_headers = [self.reverse_sanitize_content(header) for header in response_headers]
                    response_body = self.reverse_sanitize_content(response_body)
                    
                    # Build new request
                    new_request = self._helpers.buildHttpMessage(request_headers, request_body)
                    
                    # Set the new request in the Repeater tab
                    http_service = self._helpers.buildHttpService(invocation.getSelectedMessages()[0].getHttpService().getHost(), 
                                                                  invocation.getSelectedMessages()[0].getHttpService().getPort(), 
                                                                  invocation.getSelectedMessages()[0].getHttpService().getProtocol() == "https")
                    
                    self._callbacks.sendToRepeater(http_service.getHost(),
                                                   http_service.getPort(),
                                                   http_service.getProtocol() == "https",
                                                   new_request,
                                                   "Loaded Request")
                    
                    self.stdout.println("Request/Response loaded from file: {}".format(file_path))

                except Exception as e:
                    self.stdout.println("Error loading request/response from file: {}".format(str(e)))
