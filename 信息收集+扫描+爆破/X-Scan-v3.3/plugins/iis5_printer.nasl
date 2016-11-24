#
# (C) Tenable Network Security, Inc.
#
# Initial version written by John Lampe

include("compat.inc");

if(description)
{
 script_id(10657);
 script_bugtraq_id(2674);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-2001-0241");
 script_xref(name:"IAVA", value:"2001-a-0005");
 script_xref(name:"OSVDB", value:"3323");
 script_name(english:"Microsoft IIS 5.0 Malformed HTTP Printer Request Header Remote Buffer Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be execute on the remote host thru IIS" );
 script_set_attribute(attribute:"description", value:
"The remote version of the IIS web server contains a bug
which might be used by an attacker to execute arbitrary 
code on the remote system.

To exploit this vulnerability, an attacker would need to
send a specially malformed HTTP/1.1 request to the remote 
host containing an offensive payload." );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms01-023.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://www.eeye.com/html/Research/Advisories/AD20010501.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();


 summary["english"] = "Makes sure that MS01-023 is installed on the remote host";

 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
req = 'GET /NULL.printer HTTP/1.1\r\nHost: ' + crap(257) + '\r\n\r\n';

w = http_send_recv_buf(port:port, data:req);
if (w[0] =~ "HTTP/[0-9.]+ 500 13" ) security_hole(port);
