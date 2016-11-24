#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: SecuBox fRoGGz <unsecure@writeme.com>
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title, fixed CVE/OSVDB refs (3/30/2009)
# - Family change to XSS (3/31/2009)


include("compat.inc");

if(description)
{
  script_id(18216);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-1508");
  script_bugtraq_id(13561, 13563);
  script_xref(name:"OSVDB", value:"16231");

  script_name(english:"PwsPHP profil.php id Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to cross site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host runs PWSPHP (Portail Web System) a CMS written in PHP.

The remote version  of this software is vulnerable to cross-site 
scripting attack due to a lack of sanity checks on the 'skin' parameter
in the script SettingsBase.php.

With a specially crafted URL, an attacker could use the remote server
to set up a cross site script attack." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.2.3 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

script_end_attributes();


  script_summary(english:"Checks XSS in PWSPHP");
  script_category(ACT_GATHER_INFO);
  
  script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port)) exit(0);

if(get_port_state(port))
{
   foreach d ( cgi_dirs() )
   {
    buf = http_get(item:string(d,"/profil.php?id=1%20<script>foo</script>"), port:port);
    r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
    if( r == NULL )exit(0);
    if("title>PwsPHP " >< r && (egrep(pattern:"<script>foo</script>", string:r)))
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
   }
}
