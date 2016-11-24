#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14803);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2004-0811");
 script_bugtraq_id(11239);
 script_xref(name:"OSVDB", value:"10218");
 script_xref(name:"Secunia", value:"12633");
 script_xref(name:"Secunia", value:"12641");
 script_xref(name:"Secunia", value:"13025");

 script_name(english:"Apache <= 2.0.51 Satisfy Directive Access Control Bypass");
 script_summary(english:"Checks for version of Apache");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an access control bypass
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Apache web server 2.0.51. It is reported
that this version of Apache is vulnerable to an access control bypass
attack. This issue occurs when using the 'Satisfy' directive. An
attacker may gain unauthorized access to restricted resources if
access control relies on this directive.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server 2.0.52 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 if ( defined_func("bn_random") )
  script_dependencie("fedora_2004-313.nasl", "gentoo_GLSA-200409-33.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#

if ( get_kb_item("CVE-2004-0811") ) exit(0);

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default:80);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.51", string:serv))
 {
   security_hole(port);
 }
