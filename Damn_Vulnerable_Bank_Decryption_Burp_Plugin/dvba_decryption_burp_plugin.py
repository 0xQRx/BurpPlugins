from burp import IBurpExtender, IMessageEditorTab, IMessageEditorTabFactory, IResponseInfo
import base64
import javax.swing as swing

def xor_encrypt_decrypt(input_string, key="amazing"):
    key_length = len(key)
    return ''.join(chr(ord(input_string[i]) ^ ord(key[i % key_length])) for i in range(len(input_string)))

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Encryption Extension")
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        return EncryptionTab(self, controller, editable)

class EncryptionTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable
        self._txtInput = swing.JTextArea()
        self._txtInput.setEditable(editable)
        self._txtInput.setLineWrap(True)
        self._txtInput.setWrapStyleWord(True)

    def getTabCaption(self):
        return "Decrypted"

    def getUiComponent(self):
        return swing.JScrollPane(self._txtInput)

    def isEnabled(self, content, isRequest):
        return True

    def setMessage(self, content, isRequest):
        self._currentMessage = content
        self._isRequest = isRequest  # Add a flag to keep track of request type

        if content is None:
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            # Determine whether we are dealing with a request or response
            if isRequest:
                # Process request content
                request_info = self._helpers.analyzeRequest(content)
                body = content[request_info.getBodyOffset():].tostring()
            else:
                # Process response content
                response_info = self._helpers.analyzeResponse(content)
                body = content[response_info.getBodyOffset():].tostring()

            self.processMessage(body)

    def processMessage(self, data):
        try:
            json_data = self._helpers.bytesToString(data)
            start = json_data.find('"enc_data":"') + 12
            end = json_data.find('"', start)
            encrypted_data = json_data[start:end].replace("\\n", "").strip()

            decoded_data = base64.b64decode(encrypted_data)
            decrypted_data = xor_encrypt_decrypt(decoded_data)

            self._txtInput.setText(decrypted_data)
            self._txtInput.setEditable(self._editable)
            self._originalText = decrypted_data
        except Exception as e:
            self._txtInput.setText("Error processing message: " + str(e))
            self._txtInput.setEditable(False)

    def getMessage(self):
        if self.isModified():
            try:
                modified_data = self._txtInput.getText()
                encrypted_data = xor_encrypt_decrypt(modified_data)
                encoded_data = base64.b64encode(encrypted_data.encode()).decode()

                original_data = self._helpers.bytesToString(self._currentMessage)
                start = original_data.find('"enc_data":"') + 12
                end = original_data.find('"', start)
                updated_data = original_data[:start] + encoded_data + original_data[end:]

                self._currentMessageIsModified = False
                return self._helpers.stringToBytes(updated_data)
            except Exception as e:
                return self._currentMessage
        else:
            return self._currentMessage

    def isModified(self):
        return self._txtInput.isEditable() and self._txtInput.getText() != self._originalText

    def getSelectedData(self):
        selected_text = self._txtInput.getSelectedText()
        return selected_text if selected_text else None
