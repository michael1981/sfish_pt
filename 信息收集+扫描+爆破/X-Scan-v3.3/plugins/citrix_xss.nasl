#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  based on work from Tenable Network Security
#
#  Ref: Eric Detoisien <eric.detoisien@global-secure.fr>.
#
# This script is released under the GNU GPLv2


include("compat.inc");

if(description)
{
 script_id(14626);
 script_bugtraq_id(4372);
 script_cve_id("CVE-2002-0504");
 script_xref(name:"OSVDB", value:"9256");
 script_xref(name:"OSVDB", value:"9257");
  
 script_version("$Revision: 1.16 $");
 
 script_name(english:"Citrix NFuse Launch Scripts NFuse_Application Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Citrix NFuse contains a flaw that allows a remote cross
site scripting attack. 

With a specially-crafted request, an attacker can cause arbitrary code
execution resulting in a loss of integrity." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-03/0334.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


 summary["english"] = "Test Citrix NFuse_Application parameter XSS";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# start the test
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


scripts = make_list("/launch.jsp", "/launch.asp");

foreach script (scripts)
{
 req = http_get(item:string(script,"?NFuse_Application=>alert(document.cookie);</script>"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if("400 - Bad Request" >!< r && "alert(document.cookie);</script>" >< r )
 {
       security_warning(port);
       set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
       exit(0);
 }
}
