#
# (C) Tenable Network Security, Inc.
#

# Vulnerable servers:
# Pi3Web/2.0.0
#
# References
# Date:  10 Mar 2002 04:23:45 -0000
# From: "Tekno pHReak" <tek@superw00t.com>
# To: bugtraq@securityfocus.com
# Subject: Pi3Web/2.0.0 File-Disclosure/Path Disclosure vuln
#
# Date: Wed, 14 Aug 2002 23:40:55 +0400
# From:"D4rkGr3y" <grey_1999@mail.ru>
# To:bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: new bugs in MyWebServer
#


include("compat.inc");

if(description)
{
 script_id(11714);
 script_version ("$Revision: 1.15 $");

 # Note: the way the test is made will lead to detecting some
 # path disclosure issues which might be checked by other plugins 
 # (like #11226: Oracle9i jsp error). I have reviewed the reported
 # "path disclosure" errors from bugtraq and the following list
 # includes bugs which will be triggered by the NASL script. Some
 # other "path disclosure" bugs in webservers might not be triggered
 # since they might depend on some specific condition (execution
 # of a cgi, options..)
 # jfs - December 2003
 script_cve_id("CVE-2001-1372", "CVE-2002-0266", "CVE-2002-2008", "CVE-2003-0456");
 script_bugtraq_id(3341, 4035, 4261, 5054, 8075);
 script_xref(name:"OSVDB", value:"4313");
 script_xref(name:"OSVDB", value:"5406");
 script_xref(name:"OSVDB", value:"6547");
 script_xref(name:"OSVDB", value:"34884");
 
 script_name(english:"Nonexistent Page (404) Physical Path Disclosure");

 script_summary(english: "Tests for a Generic Path Disclosure Vulnerability");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to an information disclosure
attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server reveals the physical path of the webroot 
when asked for a nonexistent page.

While printing errors to the output is useful for debugging applications, 
this feature should be disabled on production servers." );
 
 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2002-02/0003.html");
 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/vulnwatch/2003-q3/0002.html");
 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2002-06/0225.html");
 
 script_set_attribute(attribute:"solution", value:
"Upgrade the server or reconfigure it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# 
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ext = make_list(".", "/", ".html", ".htm", ".jsp", ".asp", ".shtm", ".shtml",
".php", ".php3", ".php4", ".cfm");

port = get_http_port(default:80);

foreach e (ext)
{
  f = strcat("niet", rand());
  u = strcat("/", f, e);
  r = http_send_recv3(method: "GET", item: u, port:port);
  if(isnull(r)) exit(0); # Connection refused
  # Windows-like path
  resW = egrep(string: r[1]+r[2], pattern: strcat("[C-H]:(\\[A-Za-z0-9_.-])*\\", f, "\\", e));
  # Unix like path
  resU = egrep(string: r[1]+r[2], pattern: strcat("(/[A-Za-z0-9_.+-])+/", f, "/", e));
  if (strlen(resW) > 0 || strlen(resU) > 0)
  {
    if (report_verbosity > 0)
     security_warning(port, extra: 
  strcat('\nRequesting this URL:\n', build_url(port: port, qs: u), '\nrevealed:\n', resW, '\n', resU, '\n'));
    else
     security_warning(port);
    exit(0);
   }
}
