#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# To: "BugTraq" <bugtraq@securityfocus.com>
# Subject: Monkey HTTPd Remote Buffer Overflow
# Date: Sun, 20 Apr 2003 16:34:03 -0500



include("compat.inc");

if(description)
{
 script_id(11544);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2003-0218");
 script_bugtraq_id(7202);
 script_xref(name:"OSVDB", value:"7733");
 
 script_name(english: "Monkey HTTP Daemon (monkeyd) PostMethod() Function Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be run on the remote web server." );
 script_set_attribute(attribute:"description", value:
"The version of Monkey web server that you are running is vulnerable 
to a buffer overflow on a POST command with too much data.
It is possible to make this web server crash or execute arbitrary code." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Monkey server 0.6.2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "MonkeyWeb overflow with POST data");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 # The listening port in the example configuration file is 2001
 # I suspect that some people might leave it unchanged.
 script_require_ports("Services/www",80, 2001);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80); # 2001 ?
if(! get_port_state(port)) exit(0);
banner = get_http_banner(port:port);

if (banner =~ "Server: *Monkey/0\.([0-5]\.|6\.[01])")
    security_hole(port: port);
