#
# (C) Tenable Network Security
#

include( 'compat.inc' );

if(description)
{
 script_id(16045);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-1318");
 script_bugtraq_id(12053);
 script_xref(name:"OSVDB", value:"12516");

 script_name(english:"Namazu < 2.0.14 Multiple Vulnerabilities");
 script_summary(english:"Checks for the version of Namazu");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to multiple vulnerabilities.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running Namazu - a web-based search engine.

The remote version of this software is vulnerable to various flaws which
may allow an attacker to perform a cross-site scripting attack using
the remote host or to execute arbitrary code on the remote system with
the privileges of the web server."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade to Namazu 2.0.14 or newer"
    );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item:dir + "/namazu.cgi", port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 str = egrep(pattern:'<strong><a href="http://www.namazu.org/">Namazu</a> <!-- VERSION --> .* <!-- VERSION --></strong>', string:buf);
 if ( ! str ) exit(0);
 version = ereg_replace(pattern:".*<!-- VERSION --> v?(.*) <!-- VERSION -->.*", string:str, replace:"\1");
 set_kb_item(name:"www/" + port + "/namazu", value:version + " under " + dir);

 if ( ereg(pattern:"^([01]\.|2\.0\.(1[0-3]|[0-9])($|[^0-9]))", string:version) )
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}
