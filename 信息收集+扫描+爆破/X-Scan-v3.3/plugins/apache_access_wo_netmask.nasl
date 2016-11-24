#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

include("compat.inc");

if (description) {
  script_id(14177);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2003-0993");
  script_bugtraq_id(9829);
  script_xref(name:"GLSA", value:"GLSA 200405-22");
  script_xref(name:"MDKSA", value:"MDKSA-2004:046");
  script_xref(name:"OpenPKG-SA", value:"OpenPKG-SA-2004.021-apache");
  script_xref(name:"OSVDB", value:"4181");
  script_xref(name:"SSA", value:"SSA:2004-133-01");
  script_xref(name:"TSLSA", value:"TSLSA-2004-0027");
  script_xref(name:"Secunia", value:"11088");
  script_xref(name:"Secunia", value:"11681");
  script_xref(name:"Secunia", value:"11719");
  script_xref(name:"Secunia", value:"12246");
 
  script_name(english:"Apache < 1.3.31 mod_access IP Address Netmask Rule Bypass");
  script_summary(english:"Checks for Apache version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an access control bypass
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Apache web server earlier than
1.3.31. Such versions are reportedly affected by an access control
bypass vulnerability. In effect, on big-endian 64-bit platforms, Apache
fails to match allow or deny rules containing an IP address but not a
netmask. 

*****  Nessus has determined the vulnerability exists only by looking at
*****  the Server header returned by the web server running on the target.
*****  If the target is not a big-endian 64-bit platform, consider this a 
*****  false positive." );
 script_set_attribute(attribute:"see_also", value:"http://www.apacheweek.com/features/security-13" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=apache-cvs&m=107869603013722" );
 script_set_attribute(attribute:"see_also", value:"http://issues.apache.org/bugzilla/show_bug.cgi?id=23850" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 1.3.31 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 George A. Theall");

  family["english"] = "Web Servers";
  script_family(english:family["english"]);

  script_dependencie("find_service1.nasl", "global_settings.nasl", "http_version.nasl");
  if ( defined_func("bn_random") ) script_dependencie("ssh_get_info.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("http_func.inc");

if ( report_paranoia < 2 ) exit(0);

uname = get_kb_item("Host/uname");
if ( uname )
{
 if ( egrep(pattern:"i.86", string:uname) ) exit(0);
}
host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

# Check the web server's banner for the version.
banner = get_http_banner(port:port);
if (!banner) exit(0);
banner = get_backport_banner(banner:banner);

sig = strstr(banner, "Server:");
if (!sig) exit(0);

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-2][0-9]))", string:sig)) {
  security_hole(port);
}
