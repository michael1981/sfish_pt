#
# (C) Tenable Network Security, Inc.
#

# Based on Matt Moore's iis_htr_isapi.nasl
#
# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# TODO: internationalisation ?
#


include("compat.inc");

if(description)
{
 script_id(10932);
 script_bugtraq_id(4474);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2002-0071");
 script_xref(name:"IAVA", value:"2002-A-0002");
 script_xref(name:"OSVDB", value:"3325");

 script_name(english:"Microsoft IIS .HTR ISAPI Filter Enabled");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The IIS server appears to have the .HTR ISAPI filter mapped.

At least one remote vulnerability has been discovered for the .HTR
filter. This is detailed in Microsoft Advisory
MS02-018, and gives remote SYSTEM level access to the web server. 

It is recommended that, even if you have patched this vulnerability, 
you unmap the .HTR extension and any other unused ISAPI extensions
if they are not required for the operation of your site." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS02-018.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0013.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Tests for IIS .htr ISAPI filter";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check makes a request for NULL.htr

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

banner = get_http_banner(port:port);
if ( "Microsoft-IIS" >!< banner ) exit(0);

w = http_send_recv3(method:"GET", item: "/NULL.htr", port: port);
if (isnull(w)) exit(1, "the web server did not answer");

lookfor = "<html>Error: The requested file could not be found. </html>";
if (lookfor >< w[2])security_hole(port);
