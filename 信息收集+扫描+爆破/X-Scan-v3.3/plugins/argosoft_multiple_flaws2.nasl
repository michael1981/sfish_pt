#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - changed family (2/10/2009)


include("compat.inc");

if(description)
{
 script_id(16012);
 script_version("$Revision: 1.10 $");
 script_bugtraq_id(12044);
 script_xref(name:"OSVDB", value:"12505");
 script_xref(name:"Secunia", value:"13571");
 
 script_name(english:"ArGoSoft Mail Server Unspecified XSS");
 script_summary(english:"Gets the version of the remote ArGoSoft server");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a mail server that is affected by an HTML
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ArGoSoft WebMail interface.

There is a flaw in this interface which may allow an attacker
to conduct cross-site scripting (XSS) attacks against users.
No further details have been provided.

*** Nessus solely relied on the banner of this service to issue
*** this alert." );
 script_set_attribute(attribute:"see_also", value:"http://www.argosoft.com/mailserver/changelist.aspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft 1.8.7.0 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(get_port_state(port))
{
 res = http_get_cache(item:"/", port:port);
 if( res == NULL ) exit(0);
 if((vers = egrep(pattern:".*ArGoSoft Mail Server.*Version", string:res)))
 {
  if(ereg(pattern:".*Version.*\((0\.|1\.([0-7]\.|8\.([0-6]\.])))\)", string:vers))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
 }
}
