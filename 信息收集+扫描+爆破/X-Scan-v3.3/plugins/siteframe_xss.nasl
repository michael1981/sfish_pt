#
# written by K-Otik.com <ReYn0@k-otik.com>
#
# Siteframe Cross Site Scripting Bugs
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (5/27/09)
# - Updated to use compat.inc (11/20/2009)
 


include("compat.inc");

if (description)
{
 script_id(11448);
 script_version ("$Revision: 1.22 $");
 script_bugtraq_id(7140, 7143);
 script_xref(name:"OSVDB", value:"50551");
 script_xref(name:"OSVDB", value:"54766");

 script_name(english:"Siteframe search.php searchfor Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );
 script_set_attribute(attribute:"description", value:
"Siteframe 2.2.4 has a cross-site scripting bug.  An attacker may use
it to perform a cross-site scripting attack on this host. 

In addition to this, another flaw in this package may allow an
attacker to obtain the physical path to the remote web root." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determine if Siteframe is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2009 k-otik.com");
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/search.php?searchfor=", raw_string(0x22), "><script>window.alert(document.cookie);</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL ) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] +200 ", string:buf) &&
  "<script>window.alert(document.cookie);</script>" >< buf)
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}

