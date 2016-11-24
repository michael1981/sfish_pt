#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Crazy Einstein
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Standardized title (4/2/2009)


include("compat.inc");

if(description)
{
 script_id(15554);
 script_version("$Revision: 1.14 $");
 script_bugtraq_id(11471);
 script_cve_id("CVE-2004-0940");
 script_xref(name:"OSVDB", value:"11003");
 script_xref(name:"OSVDB", value:"12881");
 script_xref(name:"Secunia", value:"12898");
 script_xref(name:"Secunia", value:"19073");

 script_name(english:"Apache mod_include get_tag() Function Local Overflow");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a local buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be running a version of Apache that is older
than version 1.3.33.

This version is vulnerable to a local buffer overflow in the get_tag()
function of the module 'mod_include' when a specially crafted document 
with malformed server-side includes is requested though an HTTP session.

Successful exploitation can lead to execution of arbitrary code with 
escalated privileges, but requires that server-side includes (SSI) is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2005-816.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 1.3.33 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "os_fingerprint.nasl");
 if ( defined_func("bn_random") )
 	script_dependencie("macosx_SecUpd20041202.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

if ( get_kb_item("CVE-2004-0940") ) exit(0);

port = get_http_port(default:80);
if(!port)exit(0);
if(!get_port_state(port))exit(0);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.|3\.([0-9][^0-9]|[0-2][0-9]|3[0-2])))", string:serv))
 {
   security_warning(port);
   exit(0);
 }
