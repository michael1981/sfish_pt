#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(39436);
  script_version("$Revision: 1.1 $");

  script_name(english:"ClamAV Version Detection");
  script_summary(english:"Sends a VERSION command to clamd");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote ClamAV
installation." );
  script_set_attribute(attribute:"description", value:
"By sending a 'VERSION' command to the remote clamd anti-virus daemon,
it is possible to determine the version of the remote ClamAV software
installation." );
  script_set_attribute(attribute:"see_also", value:"http://www.clamav.net/" );
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/clamd", 3310);

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/clamd");
if (!port) port = 3310;
if (!get_port_state(port)) exit(0);

# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a VERSION command.
req = "VERSION";
send(socket:soc, data:req+'\r\n');

res = recv_line(socket:soc, length:128);
if (!strlen(res) || "ClamAV " >!< res) exit(0);

# Extract it.
version = strstr(res, "ClamAV ") - "ClamAV ";
if ("/" >< version) version = version - strstr(version, "/");

if (version)
{
  set_kb_item(name:"Antivirus/ClamAV/installed", value:TRUE);
  set_kb_item(name:"Antivirus/ClamAV/version", value:version);

  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "ClamAV version ", version, " appears to be running on the remote host based on\n",
      "the following response to a 'VERSION' command :\n",
      "\n",
      "  ", res, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
