#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38700);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1365");
  script_bugtraq_id(34790);
  script_xref(name:"OSVDB", value:"54265");
  script_xref(name:"Secunia", value:"34878");

  script_name(english:"Adobe Flash Media Server RPC Privilege Escalation (APSB09-05)");
  script_summary(english:"Checks the version number");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote media server has a privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running Adobe Flash Media Server, an application\n",
      "server for Flash-based applications.\n",
      "\n",
      "The version running on the remote host has an unspecified RPC\n",
      "vulnerability. This can reportedly be exploited to execute remote\n",
      "procedures within an server-side ActionScript file running on the\n",
      "server."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/bulletins/apsb09-05.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Flash Media Server 3.5.2 / 3.0.4 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("rtmp_detect.nasl");
  script_require_ports("Services/rtmp", 1935, 19350);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/rtmp");
if (!port) port = 1935;
if (!get_port_state(port)) exit(0);

# Send an RTMPT request.
res = http_send_recv3(
    method:"GET",
    item:'/fcs/ident',
    port:port
);
if (isnull(res)) exit(0);

# Extract the version number from the server response header.
headers = res[1];
if (
  "Server: FlashCom/" >< headers &&
  # nb: make sure we don't catch FMSAdmin.
  ">Admin user requires valid username and password.<" >!< res[2]
)
{
  server = strstr(headers, "Server:");
  server = server - strstr(server, '\r\n');

  version = strstr(server, "FlashCom/") - "FlashCom/";

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] < 3 ||
    (ver[0] == 3 && ver[1] == 0 && ver[2] < 4) ||
    (ver[0] == 3 && ver[1] > 0 && (ver[1] < 5 || (ver[1] == 5 && ver[2] < 2)))
  )
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Flash Media Server version ", version, " appears to be running on the remote\n",
        "host based on the following Server response header :\n",
        "\n",
        "  ", server, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
