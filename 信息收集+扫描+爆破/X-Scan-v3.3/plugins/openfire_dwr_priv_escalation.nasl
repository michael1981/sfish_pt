#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25343);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-2975");
  script_bugtraq_id(24205);
  script_xref(name:"OSVDB", value:"36713");

  script_name(english:"Openfire Admin Console Remote Privilege Escalation");
  script_summary(english:"Tries to access Openfire's admin console");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows unauthenticated access to its
administrative console." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Openfire / Wildfire, an instant messaging
server supporting the XMPP protocol. 

The version of Openfire or Wildfire installed on the remote host
allows unauthenticated access to a servlet, which could allow a
malicious user to upload code to Openfire via its admin console." );
 script_set_attribute(attribute:"see_also", value:"http://www.igniterealtime.org/issues/browse/JM-1049" );
 script_set_attribute(attribute:"solution", value:
"Either firewall access to the admin console on this port or upgrade to
Openfire version 3.3.1 or later" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9090);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:9090);
if (!get_port_state(port)) exit(0);


# Try to access admin console.
req = http_get(item:"/dwr/index.html", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

if (">downloader</a> (org.jivesoftware.openfire.update.PluginDownloadManager)<" >< res)
  security_hole(port);
