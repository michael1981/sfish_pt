#
# This script was written by Gregory Duchemin <plugin@intranode.com>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, updated copyright (1/23/2009)

#### REGISTER SECTION ####


include("compat.inc");

if(description)
{

script_id(10716);
 script_bugtraq_id(2788);
 script_xref(name:"OSVDB", value:"594");
 script_version ("$Revision: 1.23 $");

#Name used in the client window.

name["english"] = "OmniPro HTTPd 2.08 Encoded Space Request Script Source Disclosure";
script_name(english:name["english"]);


#Description appearing in the Nessus client window when clicking on the name.

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to information disclosure." );
 script_set_attribute(attribute:"description", value:
"OmniPro HTTPd 2.08 suffers from a security vulnerability that permits 
malicious users to get the full source code of scripting files.

By appending an ASCII/Unicode space char '%20' at the script suffix, 
the web server will no longer interpret it and rather send it back clearly 
as a simple document to the user in the same manner as it usually does to 
process HTML-like files.

The flaw does not work with files located in CGI directories (e.g cgibin, 
cgi-win)

Exploit: GET /test.php%20 HTTP/1.0

Vulnerable systems: up to release 2.08" );
 script_set_attribute(attribute:"solution", value:
"The vendor is aware of the problem but so far, no patch has been made 
available. Contact your web server vendor for a possible solution. 
Until a complete fix is available, you should remove all scripting files
from non-executable directories." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


#Summary appearing in the tooltips, only one line. 

summary["english"]="Check the presence of OmniPro HTTPd 2.08 scripts source disclosure.";
script_summary(english:summary["english"]);


#Test among the firsts scripts, no risk to harm the remote host.

script_category(ACT_GATHER_INFO);



#Copyright stuff

script_copyright(english:"(C) 2001-2009 INTRANODE");

#Category in wich attack must be stored.

family["english"]="CGI abuses";
script_family(english:family["english"]);


#Portscan the target and get back.

script_dependencie("find_service1.nasl", "http_version.nasl");


#optimization, 
#Check the presence of at least one listening web server.

script_require_ports(80, "Services/www");
 
exit(0);
}


include("http_func.inc");


#### ATTACK CODE SECTION ####

#Mandatory

function check_header(probe, port)
{ 
 local_var regex_signature, request, response, soc;
 soc = http_open_socket(port);
 if(!soc) return(0); 

 request = http_get(item:probe, port:port); 
 send(socket:soc, data:request);
 response = http_recv(socket:soc);
 http_close_socket(soc); 

 regex_signature[0] = "^Server: OmniHTTPd.*$";

 if (egrep(pattern:regex_signature[0], string:response)) return(1);
 else return(0);

}



function check(poison, port)
{ 
 local_var regex_signature, request, response, soc;
 soc = http_open_socket(port);
 if(!soc) return(0); 

 request = http_get(item:poison, port:port); 
 send(socket:soc, data:request);
 response = http_recv(socket:soc);
 http_close_socket(soc); 

 regex_signature[2] = "<?"; 


# here, a php signature.

if (regex_signature[2] >< response) return(1);
else return(0);

}




#search web port in knowledge database
#default is port 80

port = get_http_port(default:80);


if(!get_port_state(port)) exit(0);

if ( ! get_port_state(port) ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "OmniHTTPd" >!< sig ) exit(0);


Egg = "%20 ";
signature = "test.php";

probe=string("/");
if (!check_header(probe:probe, port:port)) exit(0);


poison=string("/", signature, Egg);

if (check(poison:poison, port:port))
{
report="Nessus was able to get a complete PHP source from your server.";
security_warning(port:port, extra:report);
}
else
{
report=
"OmniPro HTTPd web server is online but Nessus could not detect its release
number.";
security_warning(port:port, extra:report);
}

