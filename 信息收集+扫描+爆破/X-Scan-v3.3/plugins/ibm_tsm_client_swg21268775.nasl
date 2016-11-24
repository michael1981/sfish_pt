#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26187);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-4880", "CVE-2007-5022");
  script_bugtraq_id(25743);
  script_xref(name:"OSVDB", value:"38161");
  script_xref(name:"OSVDB", value:"38162");

  script_name(english:"IBM Tivoli Storage Manager Client Multiple Vulnerabilities (swg21268775)");
  script_summary(english:"Checks version of TSM Client from HTTP banner");

 script_set_attribute(attribute:"synopsis", value:
"The remote backup client is susceptible to multiple attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a IBM Tivoli Storage Manager (TSM) client. 

The version of the TSM client installed on the remote host reportedly
contains a buffer overflow vulnerability in its Client Acceptor Daemon
(CAD) service.  Using an HTTP request with a long Host header, a
remote attacker may be able to exploit this issue to crash the
affected host or to execute arbitrary commands with administrative
privileges. 

In addition, the use of server-initiated prompted scheduling also may
allow unauthorized access to the client's data under certain
conditions." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-054.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/480492/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IC52905" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21268775" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Storage Manager version 5.4.1.2 / 5.3.5.3 / 5.2.5.2
/ 5.1.8.1 backup-archive client or the Tivoli Storage Manager Express
5.3.5.3 client." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 1581);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/www");
if (!port) port = 1581;
if (!get_port_state(port)) exit(0);


# Grab the main page.
r = http_send_recv3(method:"GET", item:"/BACLIENT", port:port);
if (isnull(r)) exit(0);
res = strcat(r[0], r[1], '\r\n', r[2]);

# If it looks like TSM Client...
if (
  "Server: TSM_HTTP/" >< res &&
  'adsm.cadmin.clientgui.DDsmApplet.class"' >< res
)
{
  # Pull out the version number.
  ver = NULL;

  pat = ' version *= *"([0-9][0-9.]+) *"';
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        ver = item[1];
        if (ver[strlen(ver)-1] == '.') ver = substr(ver, 0, strlen(ver)-2);
        break;
      }
    }
  }
  if (!isnull(ver))
  {
    iver = split(ver, sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      iver[i] = int(iver[i]);

    if (
      iver[0] == 5 &&
      (
        (iver[1] == 1 && (iver[2] < 8 || (iver[2] == 8 && iver[3] < 1))) ||
        (iver[1] == 2 && (iver[2] < 5 || (iver[2] == 5 && iver[3] < 2))) ||
        (iver[1] == 3 && (iver[2] < 5 || (iver[2] == 5 && iver[3] < 3))) ||
        (iver[1] == 4 && (iver[2] < 1 || (iver[2] == 1 && iver[3] < 2)))
      )
    )
    {
      report = string(
        "According to its banner, version ", ver, " of IBM Tivoli Storage Manager\n",
        "Client is installed on the remote host.\n"
      );
      security_hole(port:port, extra:report);
    }
  }
}
