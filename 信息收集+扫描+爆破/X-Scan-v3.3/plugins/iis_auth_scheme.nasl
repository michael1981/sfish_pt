#
# (C) Tenable Network Security, Inc.
#

# The following HTTP requests have been provided as examples by 
# David Litchfield (david@nextgenss.com): 
#
# GET / HTTP/1.1 
# Host: iis-server 
# Authorization: Basic cTFraTk6ZDA5a2xt 

# GET / HTTP/1.1 
# Host: iis-server 
# Authorization: Negotiate TlRMTVNTUAABAAAAB4IAoAAAAAAAAAAAAAAAAAAAAAA=



include("compat.inc");

if(description)
{
 script_id(11871);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2002-0419");          
 script_bugtraq_id(4235);
 script_xref(name:"OSVDB", value:"13426");

 script_name(english:"Microsoft IIS Authentication Method Enumeration");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of IIS which allows
remote users to determine which authentication schemes are required
for confidential web pages.

That is, by requesting valid web pages with purposely invalid
credentials, you can ascertain whether or not the authentication
scheme is in use.  This can be used for brute-force attacks against
known USerIDs." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq;m=101535399100534;w=2" );
 script_set_attribute(attribute:"solution", value:
"If the application allows, disable any authentication methods that are not 
used in the IIS Properties interface." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Find IIS authentication scheme");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

auth[0] = "- IIS Basic authentication";
auth[1] = "- IIS NTLM authentication";
req[0] = string("GET / HTTP/1.1\r\nHost: ", get_host_name(), "\r\nAuthorization: Basic cTFraTk6ZDA5a2xt\r\n\r\n");
req[1] = string ("GET / HTTP/1.1\r\nHost: ", get_host_name(), "\r\nAuthorization: Negotiate TlRMTVNTUAABAAAAB4IAoAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n");
flag=0;

mywarning = string(
  "\n",
  "The following authentication methods are enabled on the remote\n",
  "webserver.\n"
);

for (i=0; req[i]; i++) {
  res = http_send_recv3(method:"GET", item:req[i], port:port);
  if (isnull(res)) exit(1, "The remote web server did not respond.");

  if (res[2] =~ "401 Unauthorized" && egrep(string:res[2], pattern:"Server:.*IIS")){
    mywarning = mywarning + auth[i];
    flag++;
  }
}

if (flag) security_warning(port:port, extra:mywarning);
exit(0);



