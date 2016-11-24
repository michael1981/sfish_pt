#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Released under the GNU GPL v2
#  Ref: jamie fisher <contact_jamie_fisher@yahoo.co.uk>
#
# Changes by Tenable :
# - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if (description)
{
 script_id(18364);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(13722);
 script_xref(name:"OSVDB", value:"16749");
 script_xref(name:"OSVDB", value:"16750");
 script_xref(name:"OSVDB", value:"16751");

 script_name(english:"Sambar Server Administrative Interface Multiple XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
cross-site scripting issues." );
 script_set_attribute(attribute:"description", value:
"The remote host runs the Sambar web server. 

The remote version of this software is vulnerable to multiple
cross site scripting attacks.

With a specially crafted URL, an attacker can use the remote 
host to perform a cross site scripting against a third party." );
 script_set_attribute(attribute:"solution", value:
"Upgrade at least to version 6.2.1." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determine if Sambar server is prone to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d ( cgi_dirs() )
{
 url = string(d, '/search/results.stm?indexname=>"><script>foo</script>&style=fancy&spage=60&query=Folder%20name');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
#<FONT SIZE="+3">S</FONT>AMBAR 
#<FONT SIZE="+3">S</FONT>EARCH 
#<FONT SIZE="+3">E</FONT>NGINE</H2>
 
 if ( ">S</FONT>AMBAR" >< buf  && "<script>foo</script>" >< buf )
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
