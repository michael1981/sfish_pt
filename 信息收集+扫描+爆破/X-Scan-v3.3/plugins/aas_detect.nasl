#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38760);
  script_version("$Revision: 1.2 $");

  script_name(english:"A-A-S Application Access Server Detection");
  script_summary(english:"Looks at the server's initial banner");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server is used for remote control of a Windows host."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "A-A-S Application Access Server, a web-based tool for remotely\n",
      "managing a Windows host, is running on this port according to its\n",
      "banner."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.klinzmann.name/a-a-s/index_en.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Ensure that use of the program agrees with the organization's\n",
      "acceptable use and security policies.\n",
      "\n",
      "If so, consider filtering incoming traffic to this port."
    )
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 6262);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:6262, embedded: 0);


 # Check the server's banner.
banner = get_http_banner(port:port);
if (!banner || "Server:" >!< banner) exit(0);

server = strstr(banner, "Server:");
server = server - strstr(server, '\r\n');

if (
  "Server: AAS/" >< server &&
  'Basic realm="Access for AAS"' >< banner
)
{
  set_kb_item(name:string("www/", port, "/aas"), value:TRUE);

  if (report_verbosity > 0)
  {
    version = strstr(server, "AAS/") - "AAS/";
    report = string(
      "\n",
      "AAS version ", version, " appears to be running on the remote host based\n",
      "on the following Server response header :\n",
      "\n",
      "  ", server, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
