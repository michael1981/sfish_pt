#
# (C) Tenable Network Security, Inc.
#

# Thanks to RFP for his explanations.
#


include("compat.inc");

if(description)
{
 script_id(10410);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0350");
 script_bugtraq_id(1216);
 script_xref(name:"OSVDB", value:"312");

 script_name(english:"ISS ICEcap Default Password");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application with a default password." );
 script_set_attribute(attribute:"description", value:
"The ICEcap package has a default login of 'iceman' with no password.

An attacker may use this fact to log into the console and/or push 
false alerts on port 8082.

In addition to this, an attacker may inject code
in ICEcap v2.0.23 and below." );
 script_set_attribute(attribute:"see_also", value:"http://advice.networkice.com/advice/Support/KB/q000166/" );
 script_set_attribute(attribute:"solution", value:
"Set a strong password on the 'iceman' account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"logs into the remote ICEcap subsystem");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/ICEcap", 8082);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/ICEcap");
if(!port)port = 8082;

if(get_port_state(port))
{
    code = http_get_cache(item:"/", port:port);
    if(code && ereg(string:code, pattern:"^HTTP/[0-9]\.[0-9] 401 .*"))
    {
     soc = open_sock_tcp(port);
     if ( ! soc )exit(0);
     s = http_get(item:"/", port:port);
     s = s - string("\r\n\r\n");
     s = s + 
     	string("\r\n") + 
        string("Authorization: Basic aWNlbWFuOiUzQjclQzYlRkU=\r\n\r\n");
     send(socket:soc, data:s);
     code = recv_line(socket:soc, length:1024);
    # r = http_recv(socket:soc);
     http_close_socket(soc);
     if(ereg(string:code, pattern:"^HTTP/[0-9]\.[0-9] 200 .*"))
      {
       security_warning(port);
      }
    }
}
   
   

