#
# written by K-Otik.com <ReYn0@k-otik.com>
#
# Basit cms Cross Site Scripting Bugs
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#


include("compat.inc");

if (description)
{
 script_id(11445);
 script_bugtraq_id(7139);
 script_xref(name:"OSVDB", value:"50539");
 script_xref(name:"OSVDB", value:"50540");
 script_version ("$Revision: 1.22 $");

 script_name(english:"Basit CMS Multiple Script XSS");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"Basit cms 1.0 has a cross-site scripting bug.  An attacker may use it
to perform a cross-site scripting attack on this host. 

In addition to this, it is vulnerable to a SQL insertion attack which
may allow an attacker to get the control of your database." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-03/0275.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determine if Basit cms is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2009 k-otik.com");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

dir = make_list(cgi_dirs());


foreach d (dir)
{
 url = string(d, "/modules/Submit/index.php?op=pre&title=<script>window.alert(document.cookie);</script>");
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

