#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: superpetz <superpetz@hushmail.com>
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, added additional OSVDB ref (4/28/09)


include("compat.inc");

if(description)
{
  script_id(15540);
  script_version("$Revision: 1.13 $");
  script_cve_id("CVE-2002-0230", "CVE-2002-2011");
  script_bugtraq_id(4565);
  script_xref(name:"OSVDB", value:"8661");
  script_xref(name:"OSVDB", value:"54110");

  script_name(english:"Faq-O-Matic fom.cgi Multiple Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"A web CGI is vulnerable to Cross Site Scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Faq-O-Matic, a CGI-based system that automates 
the process of maintaining a FAQ.

The remote version of this software is vulnerable to cross-site scripting 
attacks in the script 'fom.cgi'.

With a specially crafted URL, an attacker can cause arbitrary code 
execution resulting in a loss of integrity." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
 script_end_attributes();


  script_summary(english:"Checks Faq-O-Matic XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("cross_site_scripting.nasl");
  exit(0);
}

# the code!

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

# nb: avoid false-posiives caused by not checking for the app itself.
if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);


function check(req)
{
  local_var buf, r;
  buf = http_get(item:string(req,"/fom/fom.cgi?cmd=<script>foo</script>&file=1&keywords=nessus"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
}

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
foreach dir (cgi_dirs()) check(req:dir);
