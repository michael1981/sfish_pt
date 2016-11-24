#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#


include("compat.inc");

if(description)
{
 script_id(10677);
 script_xref(name:"OSVDB", value:"561");
 script_version ("$Revision: 1.17 $");

 script_name(english:"Apache mod_status /server-status Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server discloses information about its status." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain an overview of the remote Apache web server's
activity and performance by requesting the URL '/server-status'.  This
overview includes information such as current hosts and requests being
processed, the number of workers idle and service requests, and CPU
utilization." );
 script_set_attribute(attribute:"solution", value:
"If required, update Apache's configuration file(s) to either disable
mod_status or ensure that access is limited to valid users / hosts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 summary["english"] = "Requests /server-status";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 StrongHoldNet");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
str = "Apache Server Status";

if(get_port_state(port))
{
  buffer = http_get(item:"/server-status", port:port);
  data = http_keepalive_send_recv(port:port, data:buffer);
  if( str >< data )
  {
   security_warning(port);
  }
}
