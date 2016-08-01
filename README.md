#Burp-Non-HTTP-Extension
This burp extension adds two new features to BurpSuite.
 1.	A configurable DNS server. This will route all DNS requests to Burp or preconfigured hosts. It makes it easier to send mobile or thick client traffic to Burp. You need to create invisible proxy listeners in BurpSuite for the Burp to intercept HTTP traffic or you can use the second feature of this extension to intercept binary/non-http protocols.
 2.	A Non-HTTP MiTM Intercepting proxy. This extension allows you to create multiple listening ports that can MiTM server side services. It also uses Burp's CA cert so that if the browser or mobile device is already configured to access SSL/TLS requests using this cert then the encrypted binary protocols will be able to connect without generating errors too. It also provides the ability to automatically match and replace hex or strings as they pass through the proxy or you can use custom python code to manipulate the traffic.
 
##DNS Sever Configuration
![](NonHTTPProxy/screenshots/Dns%20Config.PNG)
The DNS server configuration allows control over the most common DNS settings. You can configure it to send all traffic to the same IP address as Burp or you can use a Custom Hosts File to configure only some hosts to be forward to Burp while others can be forwarded to other hosts. 

The DNS server automatically starts with the IP address of the last interface you set in the Interface input box. Changing the interface number will automatically change the IP address. The server will need to be restarted for this change to take effect.
The Custom Hosts File is not related at all to your normal hosts file and will over ride it. If the ‘Use DNS Response IP’ checkbos is checked (default) then the extension will resolve all hosts not in the Custom hosts file to which ever IP address is set in the ‘DNS Response IP’ input box. If this box is not checked then the extension will resolve the Real IP address unless it has been overridden in the ‘Custom Hosts File’
![](NonHTTPProxy/screenshots/dns%20requests.png)

##Non-HTTP MiTM proxy
This proxy has several features built in.

 - All requests and responses are saved to a sqlite database and can be exported or imported into the tool. 
 - Automatic Match and Replace Rules that are customizable based on the direction of traffic. (Client to Server, Server to Client, or Both.
 - Match and replace rules support both hex and string replacement. 
 - Manual Interception binary protocols and change them before sending them back to the server or client. Just like the normal Burp proxy but with binary streams.
 - Python Code can be used instead of the normal Match and Replace Rules for more advancing mangling of requests and responses.
 - 
##Configure the proxies

![](NonHTTPProxy/screenshots/serverConfig.PNG)

To perform normal intercepting of binary traffic of applications you can set the DNS IP address to the extension’s IP address and then create a Listener Under ‘Server Config’. This requires that you know the hostname and Port the application is trying to connect. You can switch to the ‘DNS History’ Tab to view the DNS queries. This will five you the host name. To find the port you can run lister.py (https://github.com/summitt/lister) and it will list the client IP and ports that are trying to connect to you. You could also run wireshark but lister.py will filter this information for you. 

Once you know the right host name and port you can configure these settings as shown above. If the service is using SSL then you need to export burp’s CA cert to the same folder that Burp is running out of for the extension to find it and generate certs that will pass certificate verification. Then you can check the SSL check box before adding the proxy. 

The proxy does not start until ‘enable’ is checked in the table.

Once the proxy is started you can intercept it in real time. All your traffic will be logged into the TCP History Tab and stored locally in a sqlite database. The database can be exported or imported from the Server Configuration Tab. In addition, if Burp crashes or you close burp without saving the TCP History it will still be automatically loaded when you start Burp. 
##Manual Intercept Traffic
![](NonHTTPProxy/screenshots/Intercepted%20Binary.png)
Clicking on the TCP Intercept Tab will allow to enable and disable Manual Intercepting. This will be very similar to intercepting HTTP traffic with burp. If the data sent is just strings then it’s very simple to just replace text or attempt modification to the request. If the application is sending serialized objects or protobuffs then you will need to switch between Raw and Hex mode to ensure the data is encoded correctly and length checks are correct.
##Automated Manipulation of Traffic
Once you have your ideal payload you can automatically match and replace in the Automation Tab. 
![](NonHTTPProxy/screenshots/Automation.PNG)

If the ‘Enable Python Manger’ is left uncheck (default) then the Match and Replace Rules are used. It supports both hex, string, and directional replacement. The ‘#’ can be used to comment out a line and rules are updated as soon as you press a single key.
If you want to replace the string ‘test’ with ‘hacked’ then you could use the following rule:
```
test||hacked
```
This will affect traffic in both directions. You could make it serve to client only by using the following rule:
```
test||hacked||c2sOnly
```
You could also perform the same replacement as hex using the following rule:
```
0x74657374||6861636B6565||c2sOnly
```

##Python Mangler
The previous example if great for quickly fuzzing the request but more complicated examples may require actual coding. The Python Mangler was built to provide fare more control of the requests and responses. You may even be able to import a library to extract the data into a more easily editable form and covert it back before sending to the server. The PyManger must have at the minimum the following structure. 

```
def mangle(input, isC2S):
	return input
```
The ‘input’ variable is a byte array, the ‘isC2S’ variable is a Boolean value, and the output must also be a byte array (though python seems somewhat forgiving here). This will allow directional specifying changes the traffic. 
Using PyMangler you can perform the same rule change above by writing the following code.
```
def mangle(input, isC2S):
	if isC2S:
		input = input.replace(‘test’,’hacked’)
		return input
```
You can import external libraries, create classes, and do anything you can do in normal python as long as there is a ‘mangle’ function with the same inputs to process the traffic. If you import custom classes they will need to be placed in the same folder that is running BurpSuite unless they are in your path. 

 
 

