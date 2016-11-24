#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20217);
  script_version("$Revision: 1.10 $");

  script_name(english:"iTunes Music Sharing Enabled");
  script_summary(english:"Checks whether music sharing is enabled in iTunes");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that may not match your
corporate security policy." );
 script_set_attribute(attribute:"description", value:
"The version of iTunes on the remote host is configured to stream music
between hosts. 

Such song sharing may not be in accordance with your security policy." );
 script_set_attribute(attribute:"solution", value:
"Disable song sharing if desired or limit access to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3689);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = 3689;
if (!get_port_state(port)) exit(0);


# Look for the iTunes banner.
banner = get_http_banner(port:port);
if (!banner) exit(0);
if ("DAAP-Server: iTunes/" >< banner) {
  req = http_get(item:"daap://" + get_host_ip() + ":" + port+ "/server-info", port:port);
  res = http_keepalive_send_recv(data:req, port:port);
  if ( res =~ "HTTP/1.1 200 OK" )
   {
    set_kb_item(name:"iTunes/" + port + "/enabled", value:TRUE);
    security_note(port);
   }
}
