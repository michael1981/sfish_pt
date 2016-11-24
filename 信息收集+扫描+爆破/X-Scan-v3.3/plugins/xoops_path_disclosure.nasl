#
# (C) Tenable Network Security, Inc.
#

# Ref :
#  Date: 20 Mar 2003 19:58:55 -0000
#  From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
#  To: bugtraq@securityfocus.com
#  Subject: [SCSA-011] Path Disclosure Vulnerability in XOOPS
#
# This check will incidentally cover other flaws.


include("compat.inc");

if(description)
{
 script_id(11439);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2002-0216", "CVE-2002-0217", "CVE-2002-1802");
 script_bugtraq_id(3977, 3978, 3981, 5785, 6344, 6393);
 script_xref(name:"OSVDB", value:"9287");
 script_xref(name:"OSVDB", value:"9288");
 script_xref(name:"OSVDB", value:"9392");
 
 script_name(english:"XOOPS 1.0 RC1 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of XOOPS installed on the remote host is affected by SQL
injection, cross-site scripting, and information disclosure." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=104820295115420&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=101232435812837&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=101232476214247&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for XOOPS");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("xoops_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/xoops"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];

 r = http_send_recv3(method:"GET", item:string(d, "/index.php?xoopsOption=nessus"), port:port);
 if (isnull(r)) exit(0);
 if(egrep(pattern:".*Fatal error.* in <b>/.*", string:r[2]))
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}
