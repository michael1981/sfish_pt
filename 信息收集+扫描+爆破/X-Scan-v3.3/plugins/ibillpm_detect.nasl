#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID

# References:
# Date:  Thu, 25 Oct 2001 12:21:37 -0700 (PDT)
# From: "MK Ultra" <mkultra@dqc.org>
# To: bugtraq@securityfocus.com
# Subject: Weak authentication in iBill's Password Management CGI


include("compat.inc");

if(description)
{
 script_id(11083);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2001-0839");
 script_bugtraq_id(3476);
 script_xref(name:"OSVDB", value:"13978");
  
 script_name(english:"iBill ibillpm.pl Password Generation Weakness");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a CGI application that is affected by
a security bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running iBill, an internet billing application.
Some versions of the 'ibillpm.pl' CGI use a weak password management
system that can be brute-forced.

** No flaw was tested. Your script might be a safe version." );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=100404371423927&w=2" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/ibillpm.pl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"ibillpm.pl", port:port);
if(res)security_hole(port);
# Note: we could try to access it. If we get a 403 the site is safe.
