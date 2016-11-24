#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31656);
 script_cve_id("CVE-2005-2728", "CVE-2005-2970");
 script_bugtraq_id(14660, 15762);
 script_xref(name:"OSVDB", value:"18977");
 script_xref(name:"OSVDB", value:"20462");
 script_version("$Revision: 1.4 $");
 
 script_name(english:"Apache < 2.0.55 Multiple DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote version of Apache is vulnerable to a denial of service
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache which is
older than 2.0.55. 

This version is vulnerable to a denial of service attack when
processing a large byterange request, as well as a flaw in the
'worker.c' module which might allow an attacker to force this service
to consumme excessive amounts of memory. 

An attacker might exploit this flaw to disable this service remotely." );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.0.55 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
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

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.([0-9][^0-9]|[0-4][0-9]|5[0-4])", string:serv))
 {
   security_warning(port);
 } 
