#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15924); 
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(11839);
 script_xref(name:"OSVDB", value:"12250");
 script_xref(name:"OSVDB", value:"12239");

 script_name(english:"Blog Torrent < 0.81 btdownload.php Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a application that is affected by 
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"There is a remote directory traversal vulnerability in 
Blog Torrent, a Web based application that allows users 
to host files for Bit Torrents.

There is a cross site scripting issue in the remote 
version of this software which may allow an attacker to set 
up attacks against third parties by using the remote server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BlogTorrent 0.81." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Looks for a XSS in Blog Torrent.");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss" ) ) exit(0);

foreach dir ( cgi_dirs() )
{
 url = dir + "/btdownload.php?type=torrent&file=<script>foo</script>";
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(0);
 if ( "<script>foo</script>" >< res[2] )
 {
  security_warning ( port );
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 } 
}
