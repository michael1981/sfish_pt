#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11451);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-1999-1479");
 script_bugtraq_id(2265);
 script_xref(name:"OSVDB", value:"13537");

 script_name(english:"Matt Wright textcounter.pl Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a CGI installed that may allow arbitrary
code execution on the remote system." );
 script_set_attribute(attribute:"description", value:
"The CGI 'textcounter' is installed. This CGI has
a well known security flaw that lets an attacker execute 
arbitrary commands with the privileges of the http daemon 
(usually root or nobody)." );
 script_set_attribute(attribute:"solution", value:
"remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/textcounter.pl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
  res = http_send_recv3(method:"GET", item:string(dir,"/textcounter.pl"), port:port);
  if(isnull(res)) exit(1,"Null response to /textcounter.pl request");

  if(res[0] =~ "^HTTP/1\.[0-9.] +200 +") security_hole(port);
}
