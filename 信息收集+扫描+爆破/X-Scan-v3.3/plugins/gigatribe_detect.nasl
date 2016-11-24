#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(35468);
  script_version("$Revision: 1.3 $");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server appears to be used for peer-to-peer file
sharing." );
 script_set_attribute(attribute:"description", value:
"According to its banner , the remote web server is from GigaTribe, a
private peer-to-peer file sharing application." );
 script_set_attribute(attribute:"see_also", value:"http://www.gigatribe.com/en/about" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this software is compliant with your organization's
acceptable use and security policies." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

  script_name(english: "GigaTribe Detection");
  script_summary(english: "Look for GigaTribe web server banner");
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_family(english:"Peer-To-Peer File Sharing");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 3728);
  exit(0);
}

#
include("global_settings.inc");
include ("misc_func.inc");
include ("http.inc");

port = get_http_port(default: 3728);
if (! port) exit(0);

banner = get_http_banner(port:port);
if (!banner || "Server:" >!< banner) exit(0);

server = strstr(banner, "Server:");
server  = server - strstr(server, '\r\n');
if ("GigaTribe/" >!< server) exit(0);

version = strstr(server, "GigaTribe/") - "GigaTribe/";
if (version !~ "^[0-9][0-9.]+") version = "unknown";
set_kb_item(name:'gigatribe/version/'+port, value:version);

if (report_verbosity)
{
  if (version == "unknown") report = "An unknown version of GigaTribe";
  else                      report = "GigaTribe version " + version;

  report = string(
    "\n",
    report, " appears to be running on the remote host\n",
    "based on the following Server response header :\n",
    "\n",
    "  ", server, "\n"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
