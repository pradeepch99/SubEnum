# --------------------------------
# Hidden Subdomain Enumerator
# Author : #pradeepch99
# Credits : @nagaraju, @jashwanth
# ---------------------------------
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IHttpRequestResponse
from burp import IMessageEditorController
from java.lang import RuntimeException
from java.net import URL
from javax.swing import JMenuItem
import string
import urllib2
from urlparse import urlparse
import tldextract

import javax

# Scan first 1 KB of messages
MESSAGE_LIMIT = 1024 

class BurpExtender(IBurpExtender, IContextMenuFactory):
    
    # Implement IBurpExtender
    def	registerExtenderCallbacks(self, callbacks):

        # Set extension name
        callbacks.setExtensionName("SubEnum")

        # Callbacks object
        self.callbacks = callbacks

        # Helpers object
        self._helpers = callbacks.getHelpers()

        # Register a factory for custom context menu items
        callbacks.registerContextMenuFactory(self)
		
        self.website = javax.swing.JTextField()

        return

    # Create a menu item if the appropriate section of the UI is selected
    def createMenuItems(self, invocation):
        
        menu = []

        # Which part of the interface the user selects
        ctx = invocation.getInvocationContext()

        # Message Viewer Req/Res, Site Map Table, and Proxy History will show menu item if selected by the user
        if ctx == 2 or ctx == 3 or  ctx == 4 or ctx == 5 or ctx == 6:
            menu.append(JMenuItem("Enumerate Subdomains", None, actionPerformed=lambda x, inv=invocation: self.SubScan(inv)))

        return menu if menu else None

    def SubScan(self, invocation):

        # Check initial message for proper request/response and set variables - Burp will not return valid info otherwise
        try:
            invMessage = invocation.getSelectedMessages()
            message = invMessage[0]
            originalHttpService = message.getHttpService()
            self.originalMsgProtocol = originalHttpService.getProtocol()
            self.originalMsgHost = originalHttpService.getHost()
            self.originalMsgPort = originalHttpService.getPort()
            self.originalMsgUrl = self.originalMsgProtocol + '://' + self.originalMsgHost
            
            domain = str(self.originalMsgHost)
            ext = tldextract.extract(domain)
            domain1 = ext.domain+'.'+ext.suffix
            
            siteMap = self.callbacks.getSiteMap('')
            lastURL = ''
            print '\n Enumerating %s subdomains.\n' % domain1            
            if siteMap:
              for item in siteMap:
                try:
                  request = item.getRequest()
                  if request:
                    service = item.getHttpService().toString()
                    if service != lastURL:
                      if domain1 in service:
                        print ' [+] %s' %service
                        lastURL = service

                except Exception, e:
                  print 'Error while getting subdomain'
                  continue
            else:
              print 'The Target Site Tree is Empty'

        except:
            e = sys.exc_info()[0]
            print "Something went wrong\n"
            raise RuntimeException(e)