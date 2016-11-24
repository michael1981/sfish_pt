#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# References:
# Date:  Fri, 29 Jun 2001 13:01:21 -0700 (PDT)
# From: "Extirpater" <extirpater@yahoo.com>
# Subject: 4 New vulns. vWebServer and SmallHTTP
# To: bugtraq@securityfocus.com, vuln-dev@securityfocus.com
#


include("compat.inc");

if(description)
{
 script_id(11071);
 script_bugtraq_id(2975);
 script_xref(name:"OSVDB", value:"12403");
 script_xref(name:"OSVDB", value:"32391");
 script_xref(name:"OSVDB", value:"37732");
 script_xref(name:"OSVDB", value:"56515");
 script_xref(name:"Secunia", value:"25809");
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2001-1248", "CVE-2007-3407");
 script_name(english:"Multiple Web Server Encoded Space (%20) Request ASP Source Disclosure");
 script_summary(english:"Downloads the source of ASP scripts");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to get the source code of the remote ASP scripts by
appending a '%20' at the end of the request.

ASP source code usually contains sensitive information such as logins
and passwords.

This has been reported in Simple HTTPD (shttpd), Mono XSP for ASP.NET
and vWebServer. This type of request may affect other web servers as
well." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-12/0327.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-06/0297.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "webmirror.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(file)
{
  global_var	port;
  local_var	r;
  r = http_send_recv3(method: "GET", item:string(file, "%20"), port:port);
  if (isnull(r)) exit(0);
  if (r[0] !~ "^HTTP/.* 200 ") exit(0);
  if("Content-Type: application/octet-stream" >< r[1]){
  	security_warning(port);
	return(1);
	}
  if (("<%" >< r[2]) && ("%>" >< r[2])) {
	security_warning(port);
	return(1);
  }
 return(0);
}


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if(check(file:"/default.asp"))exit(0);
files = get_kb_list(string("www/", port, "/content/extensions/asp"));
if(isnull(files))exit(0);
files = make_list(files);
check(file:files[0]); 
