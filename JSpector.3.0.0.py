from burp import (IBurpExtender, IHttpListener, IScannerListener,
                  IExtensionStateListener, IContextMenuFactory, IScanIssue)
import re
from java.util import ArrayList
from javax.swing import JMenuItem, JOptionPane
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.net import URL


class BurpExtender(IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener, IContextMenuFactory):

    def __init__(self):
        self._exclusion_regex = re.compile(r'http://www\.w3\.org')
        self._url_pattern = re.compile(
            r'(?:http|https|ftp|ftps|sftp|file|tftp|telnet|gopher|ldap|ssh)://[^\s"<>]+')
        self._endpoint_pattern1 = re.compile(
            r'(?:(?<=["\'])/(?:[^/"\']+/?)+(?=["\']))')
        self._endpoint_pattern2 = re.compile(
            r'http\.(?:post|get|put|delete|patch)\(["\']((?:[^/"\']+/?)+)["\']')
        self._endpoint_pattern3 = re.compile(
            r'httpClient\.(?:post|get|put|delete|patch)\(this\.configuration\.basePath\+["\']/(?:[^/"\']+/?)+["\']')
        self._invocation = None
        self._scanned_js_files = set()

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("JSpector")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)

        print("JSpector extension loaded successfully.\nWarning: the size of the output console content is limited, we recommend that you save your results in a file.\n")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        def is_js_file(url):
            return url.lower().endswith('.js')
        if not messageIsRequest and self._callbacks.isInScope(messageInfo.getUrl()):
            js_url = messageInfo.getUrl().toString()

            if js_url not in self._scanned_js_files:
                self._scanned_js_files.add(js_url)
                response = messageInfo.getResponse()

                if response:
                    response_info = self._helpers.analyzeResponse(response)
                    headers = response_info.getHeaders()
                    content_type = next((header.split(':', 1)[1].strip(
                    ) for header in headers if header.lower().startswith('content-type:')), None)
                    content_type_is_js = content_type and 'javascript' in content_type.lower()

                    if content_type_is_js or is_js_file(js_url):
                        body = response[response_info.getBodyOffset():]
                        urls = self.extract_urls_from_js(body)

                        if urls:
                            self.create_issue(messageInfo, urls)

                        if toolFlag == self._callbacks.TOOL_PROXY:
                            self._scanned_js_files.add(js_url)

    def extract_urls_from_js(self, js_code):
        urls = set(re.findall(self._url_pattern, js_code))
        endpoints1 = set(re.findall(self._endpoint_pattern1, js_code))
        endpoints2 = set(re.findall(self._endpoint_pattern2, js_code))
        endpoints3 = set(re.findall(self._endpoint_pattern3, js_code))

        urls = set(url for url in urls if not self._exclusion_regex.search(url))

        return urls.union(endpoints1, endpoints2, endpoints3)

    def create_issue(self, messageInfo, urls):
        urls_found, endpoints_found = self.sort_urls_endpoints(urls)
        issue = JSURLsIssue(self._helpers, messageInfo, urls, urls_found, endpoints_found)
        self._callbacks.addScanIssue(issue)
        js_full_url = messageInfo.getUrl().toString()
        self.output_results(urls, js_full_url)

    def extensionUnloaded(self):
        print("JSpector extension unloaded.")

    def newScanIssue(self, issue):
        pass

    def createMenuItems(self, invocation):
        self._invocation = invocation
        menu_items = ArrayList()

        menu_item1 = JMenuItem("Export URLs to clipboard",
                               actionPerformed=self.export_urls_to_clipboard)
        menu_items.add(menu_item1)

        menu_item2 = JMenuItem("Export endpoints to clipboard",
                               actionPerformed=self.export_endpoints_to_clipboard)
        menu_items.add(menu_item2)

        menu_item4 = JMenuItem("Export all results to clipboard",
                               actionPerformed=self.export_results_to_clipboard)
        menu_items.add(menu_item4)

        return menu_items

    def is_js_file(self, url):
        return url.lower().endswith('.js')

    def output_results(self, urls, js_full_url):
        urls_list, endpoints_list = self.sort_urls_endpoints(urls)

        print("JSpector results for {}:".format(js_full_url))
        print("-----------------")

        print("URLs found ({}):\n-----------------\n{}".format(len(urls_list),
              '\n'.join(urls_list)))

        print("\nEndpoints found ({}):".format(len(endpoints_list)))
        if endpoints_list:
            print("-----------------\n{}".format('\n'.join(endpoints_list)))
        else:
            print("No endpoints found.")
        print("-----------------")

    def sort_urls_endpoints(self, urls):
        urls_list = []
        endpoints_list = []

        false_positive_endpoints = ["replace("]

        for url in urls:
            if re.match('^(?:http|https|ftp|ftps|sftp|file|tftp|telnet|gopher|ldap|ssh)://', url):
                # customization: only consider in scope URLs
                try:
                    if self._callbacks.isInScope(URL(url)):
                        urls_list.append(url)
                except:
                    print "Url " + url + "cannot be coerced to Java URL"
            else:
                skip=False
                # customization: skip false positive such as 'replace(/\\...'
                for false_positive in false_positive_endpoints:
                    if false_positive in url:
                        skip=True
                        break
                if not skip:
                    endpoints_list.append(url)

        urls_list.sort()
        endpoints_list.sort()

        return urls_list, endpoints_list


class JSURLsIssue(IScanIssue):

    def __init__(self, helpers, messageInfo, urls, urls_found, endpoints_found):
        self._helpers = helpers
        self._httpService = messageInfo.getHttpService()
        self._url = messageInfo.getUrl()
        self._urls = urls
        self._urls_list = urls_found
        self._endpoints_list = endpoints_found

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return []

    def getHttpService(self):
        return self._httpService

    def getIssueName(self):
        return "JSPector results"

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "The following URLs were found in a JavaScript file. This information may be useful for further testing."

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        urls_list = self._urls_list
        endpoints_list = self._endpoints_list

        details = self.build_list("URLs found", urls_list)
        details += self.build_list("Endpoints found", endpoints_list)

        return details

    def getRemediationDetail(self):
        return None

    @staticmethod
    def build_list(title, items):
        if not items:
            return ""

        details = "<b>{title} ({num_items}):</b>".format(title=title,
                                                         num_items=len(items))
        details += "<ul>"

        for item in items:
            details += "<li>{item}</li>".format(item=item)

        details += "</ul>"

        return details
