#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35328);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(33180);
  script_xref(name:"Secunia", value:"33411");
  script_xref(name:"OSVDB", value:"51700");

  script_name(english:"Serv-U 7.x < 7.4.0.0 Multiple Command Remote DoS");
  script_summary(english:"Checks Serv-U version");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Serv-U File Server, an FTP server for
Windows. 

The installed version of Serv-U 7.x is earlier than 7.4.0.0, and is
therefore affected by a denial of service vulnerability.  By using a
specially crafted command such as XCRC, STOU, DSIZ, AVBL, RNTO, or
RMDA, it may be possible for an authenticated attacker to render the
FTP server temporarily unresponsive." );
 script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/releasenotes/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serv-U version 7.4.0.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if (!port) port = 21;

if (!get_port_state(port)) exit(0);

# Make sure the banner looks like Serv-U.
banner = get_ftp_banner(port:port);
if (!banner || " Serv-U FTP Server v" >!< banner) exit(0);

# Identify the version.
version = strstr(banner, " Serv-U FTP Server v") - " Serv-U FTP Server v";
version = version - strstr(version, " ready");

# Check the version.
if (version && version =~ "^7\.([0-3]($|[^0-9]))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Serv-U version ", version, " appears to be running on the remote host.\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
