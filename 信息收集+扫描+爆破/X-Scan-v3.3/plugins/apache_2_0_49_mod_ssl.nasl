#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12100);
 script_bugtraq_id(9826);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0113");
 script_xref(name:"OSVDB", value:"4182");
 script_xref(name:"Secunia", value:"11092");
 script_xref(name:"Secunia", value:"11705");

 script_name(english:"Apache mod_ssl Plain HTTP Request DoS");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.x which is
older than 2.0.49. Such versions are reportedly affected by a denial
of service vulnerability in the 'mod_ssl' module. An attacker could
exploit this in order to deny service to the Apache server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 2.0.49 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default:443);

transport = get_port_transport(port);

if ( ! ( t == ENCAPS_SSLv23 || 
	 t == ENCAPS_SSLv2 || 
	 t == ENCAPS_SSLv3 || 
	 t == ENCAPS_TLSv1) ) exit(0);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.(3[5-9]|4[0-8])", string:serv))
 {
   security_warning(port);
 }
