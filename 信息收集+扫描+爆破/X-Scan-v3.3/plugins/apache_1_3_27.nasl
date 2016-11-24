#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#

include("compat.inc");

if(description)
{
 script_id(11137);
 script_bugtraq_id(5847, 5884, 5887, 5995, 5996);
 script_cve_id("CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843");
 script_xref(name:"OSVDB", value:"862");
 script_xref(name:"OSVDB", value:"4552");
 script_xref(name:"OSVDB", value:"4553");
 script_version("$Revision: 1.23 $");
 
 script_name(english:"Apache < 1.3.27 Multiple Vulnerabilities (DoS, XSS)");
 script_summary(english:"Checks for version of Apache");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Apache web server older than
1.3.27. Such versions are reportedly affected by multiple
vulnerabilities :

  - There is a cross site scripting vulnerability caused by
    a failure to filter HTTP/1.1 'Host' headers that are
    sent by browsers.

  - A vulnerability in the handling of the Apache scorecard
    could allow an attacker to cause a denial of service.

  - A buffer overflow vulnerability exists in the
    'support/ab.c' read_connection() function. The ab.c file
    is a benchmarking support utility that is provided with
    the Apache web server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-10/0195.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q4/0012.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-11/0137.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2002-q4/0003.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 1.3.27 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner)exit(0);
banner = get_backport_banner(banner:banner);
serv = strstr(banner, "Server:");
if(!serv)exit(0);
 
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-6])))", string:serv))
 {
   security_hole(port);
 }
