#
# (C) Tenable Network Security, Inc.
#

# Ref: AccessX 


include("compat.inc");

if(description)
{
 script_id(15861);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2004-2474");
 script_bugtraq_id(11748);
 script_xref(name:"OSVDB", value:"12119");
 
 script_name(english:"PHPNews sendtofriend.php SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is using PHPNews, an open source news application. 
It utilizes database to store the content.

A vulnerability exists in the remote version of this software which may
allow an attacker to inject arbitrary SQL code and possibly execute 
arbitrary code, due to improper validation of user supplied input in the
'mid' parameter of script 'sendtofriend.php'." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the version 1.2.4 of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Makes a request to the remote host by supplying the mid paramter in the url");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
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

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var	r, buf;

 r = http_send_recv3(method:"GET", item:string(loc, "/phpnews/sendtofriend.php?mid='1'"), port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if ("mysql_fetch_assoc():" >< buf)
 {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
