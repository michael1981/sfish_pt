#
# (C) Tenable Network Security, Inc.
#

# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# It was modified by H D Moore to not crash the server during the test
#
# Supercedes MS01-033


include("compat.inc");

if(description)
{
 script_id(10685);
 script_version ("$Revision: 1.31 $");
 script_cve_id( "CVE-2001-0544", "CVE-2001-0545", "CVE-2001-0506", "CVE-2001-0507", "CVE-2001-0508", "CVE-2001-0500");
 script_bugtraq_id(2690, 2880, 3190, 3193, 3194, 3195);
 script_xref(name:"OSVDB", value:"568");
 script_xref(name:"OSVDB", value:"1930");
 script_xref(name:"OSVDB", value:"1931");
 script_xref(name:"OSVDB", value:"5584");
 script_xref(name:"OSVDB", value:"5606");
 script_xref(name:"OSVDB", value:"5633");
 script_xref(name:"OSVDB", value:"5736");
 script_xref(name:"IAVA", value:"2001-a-0008");
 script_xref(name:"IAVA", value:"2001-a-0010");
 
 script_name(english:"Microsoft IIS ISAPI Filter Multiple Vulnerabilities (MS01-044)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"There's a buffer overflow in the remote web server through
the ISAPI filter.
 
It is possible to overflow the remote web server and execute 
commands as user SYSTEM.

Additionally, other vulnerabilities exist in the remote web
server since it has not been patched." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS01-033.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/ms01-044.mspx" );
 script_set_attribute(attribute:"solution", value:
"Apply the patches from the bulletins above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();


 script_summary(english:"Tests for a remote buffer overflow in IIS");
 script_category(ACT_ATTACK);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
b = get_http_banner(port: port);
if ("IIS" >!< h ) exit(0);
   
     
w = http_send_recv3(method: "GET", port: port,
  item: "/x.ida?"+crap(length:220, data:"x")+"=x");
if (isnull(w)) exit(1, "the web server did not answer");
r = strcat(w[0], w[1], '\r\n', w[2]);

    # 0xc0000005 == "Access Violation"
    if ("0xc0000005" >< r)
    {
        security_hole(port);
    }

