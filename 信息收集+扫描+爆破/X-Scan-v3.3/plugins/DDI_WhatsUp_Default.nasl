#
# Copyright 2001 by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, changed family (4/13/2009)

include("compat.inc");

if(description)
{
 script_id(11004);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-1999-0508");

 script_name(english:"Ipswitch WhatsUp Gold Default Admin Account");
 script_summary(english:"WhatsUp Gold Default Admin Account");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a default set of administrative
credentials.");
 script_set_attribute(attribute:"description", value:
"This WhatsUp Gold server still has the default password for the admin
user account.  An attacker can use this account to probe other systems
on the network and obtain sensitive information about the monitored
systems.");
 script_set_attribute(attribute:"solution", value:
"Login to this system and either disable the admin account or assign
it a difficult to guess password.");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001-2009 Digital Defense Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
 {
  soc = http_open_socket(port);
  if (soc)
  {
    req = string("GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4K\r\n\r\n");
    send(socket:soc, data:req);
    buf = http_recv(socket:soc);
    http_close_socket(soc);
    if (!isnull(buf) && "Whatsup Gold" >< buf && "Unauthorized User" >!< buf)
    {
     security_hole(port:port);
    }
  }
 }
