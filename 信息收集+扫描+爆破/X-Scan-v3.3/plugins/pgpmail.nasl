#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added CAN.  Added link to the Bugtraq message archive
#
# References:
# From: joetesta@hushmail.com
# To: bugtraq@securityfocus.com, jscimone@cc.gatech.edu
# Subject: Vulnerabilities in PGPMail.pl
# Date: Thu, 29 Nov 2001 19:45:38 -0800
# 
# John Scimone <jscimone@cc.gatech.edu>.  
# <http://www.securityfocus.com/archive/82/243262>
#


include("compat.inc");

if(description)
{
 script_id(11070);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2001-0937");
 script_bugtraq_id(3605);
 script_xref(name:"OSVDB", value:"11968");
 
 name["english"] = "PGPMail.pl detection";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands might be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The 'PGPMail.pl' CGI is installed. 

Some versions (up to v1.31 a least) of this CGI do not properly filter
user input before using it inside commands.  This would allow a
cracker to run any command on your server. 

*** Note: Nessus just checked the presence of this CGI 
*** but did not try to exploit the flaws." );
 script_set_attribute(attribute:"solution", value:
"remove it from /cgi-bin or upgrade it." );
 script_set_attribute(attribute:"see_also", value:"http://online.securityfocus.com/archive/82/243262" );
 script_set_attribute(attribute:"see_also", value:"http://online.securityfocus.com/archive/1/243408" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 summary["english"] = "Checks for the presence of PGPMail.pl";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80, embedded: 0);
res = is_cgi_installed3(port:port, item:"PGPMail.pl");
if(res) security_hole(port);

