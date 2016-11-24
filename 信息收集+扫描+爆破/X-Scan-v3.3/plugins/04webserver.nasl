#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15713);
 script_cve_id("CVE-2004-1512", "CVE-2004-1513", "CVE-2004-1514");
 script_bugtraq_id(11652);
 script_xref(name:"OSVDB", value:"11606");
 script_xref(name:"OSVDB", value:"11607");
 script_xref(name:"OSVDB", value:"11608");
 script_version("$Revision: 1.11 $");
 
 script_name(english:"04WebServer Multiple Vulnerabilities (XSS, DoS, more)");
 script_summary(english:"Checks for version of 04WebServer");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to several forms of attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of 04WebServer which is older
than version 1.5. Such versions are affected by multiple
vulnerabilities :
  
  - A cross-site scripting vulnerability in the
    Response_default.html script which could allow an attacker
    to execute arbitrary code in the user's browser.

  - A log file content injection vulnerability which could
    allow an attacker to insert false entries into the log
    file.

  - A DoS vulnerability caused by an attacker specifying a
    DOS device name in the request URL." );

script_set_attribute(attribute:"see_also", value: "http://archives.neohapsis.com/archives/bugtraq/2004-11/0135.html");
script_set_attribute(attribute:"see_also", value: "http://archives.neohapsis.com/archives/bugtraq/2004-11/0191.html");
script_set_attribute(attribute:"see_also", value: "http://attrition.org/pipermail/vim/2006-August/000978.html");
script_set_attribute(attribute:"see_also", value: "http://www.security.org.sg/vuln/04webserver142.html");

 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.5 of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server: 04WebServer/(0\.|1\.([0-9][^0-9]|[0-3][0-9]|4[0-2]))", string:serv))
 {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
