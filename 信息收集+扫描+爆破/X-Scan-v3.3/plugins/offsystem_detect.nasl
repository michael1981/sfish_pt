#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33228);
  script_version("$Revision: 1.3 $");

  script_name(english:"Owner Free File System Client Detection");
  script_summary(english:"Pings an OFFSystem Client");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server acts as a distributed filesystem." );
 script_set_attribute(attribute:"description", value:
"The remote web server is an OFFSystem client.  OFFSystem (Owner-Free
Filesystem) is a distributed filesystem for peer-to-peer file sharing
in which files are stored as randomized data blocks" );
 script_set_attribute(attribute:"see_also", value:"http://offsystem.sourceforge.net/" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this software is in line with your organization's
security and acceptable use policies." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/www", 23402, 23403);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:23403);
if (!get_port_state(port)) exit(0);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);


# Unless we're paranoid, make sure it looks like OFFSystem.
if (report_paranoia < 2)
{
  res = http_get_cache(item:"/", port:port);
  if (res == NULL) exit(0);

  if (
    # OFFSystem doesn't use a Server response header.
    "Server:" >!< res &&
    # Response when remote browser access is disabled.
    "This node is not permitting browser retrieval." >!< res &&
    # Response when remote browser access is enabled.
    "HTTP/1.1 403 FORBIDDEN" >!< res &&
    # Response on localhost.
    "a placeholder page for the OFFsystem http interface." >!< res
  ) exit(0);
}


# Send a ping.
nodeid = "6988a87dc134c59a8592c8c9956fd11f5ae5ae0f";
username = "nessus";
ver = "0.19.13    win32";


postdata = string(
  username, "\t",
  ver, "\t",
  "1", "\t",
  "50885233", "\t",
  "0", "\t",
  "0", "\t",
  "5"
);
req = string(
  "POST /something/maybe/ping HTTP/1.1\r\n",
  "Host: ", get_host_name(), "/", port, "\r\n",
  "Content-Type: off/ping\r\n",
  "Content-Length: ", strlen(postdata), "\r\n",
  "OFF-Listen-Port: ", port, "\r\n",
  "OFF-Crypt-Pad: unencrypted\r\n",
  "OFF-Node-ID: ", nodeid, ":90:80\r\n",
  "\r\n",
  postdata
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# Report it if it's a ping response.
if (
  "POST /something/maybe/ping_response" >< res ||
  "Content-Type: off/ping_response" >< res
) security_note(port);
