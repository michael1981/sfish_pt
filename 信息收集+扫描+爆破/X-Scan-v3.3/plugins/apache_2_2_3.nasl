#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31659);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2006-3747");
 script_bugtraq_id(19204);
 script_xref(name:"OSVDB", value:"27588");
 
 script_name(english:"Apache < 2.2.3 mod_rewrite LDAP Protocol URL Handling Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote version of Apache is vulnerable to an off-by-one buffer
overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache which is
older than 2.2.3.

This version is vulnerable to an off-by-one buffer overflow attack in
the mod_rewrite module." );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.2.3." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

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

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.2\.([0-2][^0-9])", string:serv))
 {
   security_hole(port);
 } 
