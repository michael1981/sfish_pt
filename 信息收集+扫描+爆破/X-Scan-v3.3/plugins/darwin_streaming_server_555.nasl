#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25214);
  script_version("$Revision: 1.8 $");
  script_cve_id("CVE-2007-0748", "CVE-2007-0749");
  script_bugtraq_id(23918);
  script_xref(name:"OSVDB", value:"35975");
  script_xref(name:"OSVDB", value:"35976");

  script_name(english:"Darwin Streaming Server < 5.5.5 Multiple Remote Overflow Vulnerabilities");
  script_summary(english:"Checks RTSP server banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote RTSP server suffers from a multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Darwin Streaming Server, a media streaming
server. 

According to its banner, the version of the Darwin Streaming Server
installed on the remote host is affected by multiple buffer overflow
vulnerabilities.  An unauthenticated remote attacker may be able to
leverage these issues using specially-crafted RTSP requests to crash
the affected service or to execute arbitrary code subject to the
privileges of the user id under which it runs, generally root." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=533" );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305495" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Darwin Streaming Server 5.5.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/rtsp", 554);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/rstp");
if (!port) port = 554;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

# Grab the banner.
req = 'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n';
send(socket:soc, data:req);
r = http_recv3(socket:soc);
close(soc);
if (isnull(r)) exit(0);

h = parse_http_headers(status_line: r[0], headers: r[1]);

# Pull out the server information.
server = h["server"];
if (!server) server = h["via"];

# If it's Darwin Streaming Server...
if (stridx(server, "DSS/") == 0)
{
  ver = ereg_replace(pattern:"^DSS/([0-9\.]+) .+$", replace:"\1", string:server);
  if (ver)
  {
    iver = split (ver, sep:".", keep:FALSE);
    for (i=0; i<max_index(iver); i++)
      iver[i] = int(iver[i]);

    # Versions before 5.5.5 are affected.
    if (
      iver[0] < 5 ||
      (
        iver[0] == 5 &&
        (
          iver[1] < 5 ||
          (iver[1] == 5 && iver[2] < 5)
        )
      )
    ) 
    {
     report = strcat('Darwin Streaming Server version ', ver, 
     	' appears to be running on the\n',
        'remote host based on the following banner :\n\n',
        '  ', server, '\n' );
      security_hole(port:port, extra: report);
    }
  }
}
