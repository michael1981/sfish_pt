#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID

# Source:
# From:"Peter_Gründl" <pgrundl@kpmg.dk>
# To:"bugtraq" <bugtraq@securityfocus.com>
# Subject: KPMG-2002033: Resin DOS device path disclosure
# Date: Wed, 17 Jul 2002 11:33:59 +0200

include("compat.inc");

if(description)
{
 script_id(11048);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2002-2090");
 script_bugtraq_id(5252);
 script_xref(name:"OSVDB", value:"850");

 script_name(english:"Resin MS-DOS Device Request Path Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to disclose information about the remote host." );
 script_set_attribute(attribute:"description", value:
"Resin will reveal the physical path of the webroot when asked
for a special DOS device, e.g. lpt9.xtp

An attacker may use this flaw to gain further knowledge about
the remote filesystem layout." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a later software version." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();

 
 script_summary(english:"Tests for Resin path disclosure vulnerability");
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8282);

# Requesting a DOS device may hang some servers
# According to Peter Gründl's advisory:
# Vulnerable:
# Resin 2.1.1 on Windows 2000 Server
# Resin 2.1.2 on Windows 2000 Server
# <security-protocols@hushmail.com> added Resin 2.1.0
# Not Vulnerable:
# Resin 2.1.s020711 on Windows 2000 Server
# 
# The banner for snapshot 020604 looks like this:
# Server: Resin/2.1.s020604

banner = get_http_banner(port: port);
vulnver=0;

if ( "Resin/" >!< banner ) exit(0);

w = http_send_recv3(method:"GET", item:"/aux.xtp", port:port);
if (isnull(w)) exit(0, "the web server did not answer");
h = w[1]; r = w[2];

if (egrep(pattern: "[CDE]:\\(.*\\)*aux.xtp", string:r))
{
 path = egrep(pattern: "[CDE]:\\(.*\\)*aux.xtp", string:r);
 path = ereg_replace(pattern:".*([CDE]:\\.*aux\.xtp).*", string:path, replace:"\1");

 security_note(port);
}
