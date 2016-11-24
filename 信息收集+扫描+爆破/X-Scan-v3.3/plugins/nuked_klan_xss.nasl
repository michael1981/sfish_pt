#
# This test was rewritten by Tenable Network Security, Inc.
#
#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (3/27/09)
# - Changed family (5/21/09)


include("compat.inc");

if (description)
{
 script_id(11447);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2003-1238", "CVE-2003-1371");
 script_bugtraq_id(6916, 6917);
 script_xref(name:"OSVDB", value:"50552");
 script_xref(name:"OSVDB", value:"52891");

 script_name(english:"Nuked-Klan index.php Multiple Module Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to 
multiple issues." );
 script_set_attribute(attribute:"description", value:
"Nuked-klan 1.3b fails to sanitize user-supplied input to several
parameters before using them in the 'Team', 'News', and 'Liens'
modules to display dynamic HTML.  An attacker may leverage these
issues to launch cross-site scripting attacks against the affected
host. 

In addition to this, another flaw may allow an attacker to obtain the
physical path of the directory in which the application is installed." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-03/0275.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-02/0276.html" );
 script_set_attribute(attribute:"solution", value:
"Contact the author for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determine if Nuked-klan is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 k-otik.com");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

foreach d (cgi_dirs())
{
 url = string(d, "/index.php?file=Liens&op=", raw_string(0x22), "><script>window.alert('test');</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL ) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] +200 .*", string:buf) &&
    "<script>window.alert('test');</script>" >< buf)
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
