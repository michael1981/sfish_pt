#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, family change, output formatting (9/3/09)

include("compat.inc");

if(description)
{
 script_id(18177);
 script_version("$Revision: 1.5 $");
 
 script_name(english:"Websense Reporting Console Detection");
  script_set_attribute(
    attribute:"synopsis",
    value:"A web application running on the remote host is leaking information."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host appears to be running Websense, and connections are
allowed to the web reporting console.  A remote attacker could use
information gathered from this access to mount further attacks."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Filter incoming traffic to this port."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

 script_summary(english:"Checks for Websense reporting console");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("httpver.nasl");

 script_require_ports(8010);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = 8010;
if (get_port_state(port))
{
 req = http_get(item:"/Websense/cgi-bin/WsCgiLogin.exe", port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);

 if ("<title>Websense Enterprise - Log On</title>" >< rep)
 {
	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
	security_warning(port);
 }
}
exit(0);
