#  
#  This script is written by shruti@tenablesecurity.com. 
#  based on work done by Renaud Deraison. 
#  Ref: Announced by vendor
#


include("compat.inc");

if(description)
{
 script_id(15908);
 script_version("$Revision: 1.11 $");
 script_bugtraq_id( 11803 );
 script_xref(name:"OSVDB", value:"12178");
 
 script_name(english:"Apache Jakarta Lucene results.jsp XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote Apache Jakarta Lucene software is vulnerable to a cross-
site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Apache Jakarta Lucene, a full-featured text 
search engine library implemented in Java.

There is a cross-site scripting vulnerability in the script
'results.jsp' that may allow an attacker to steal the cookies of
legitimate users on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Software Foundation Jakarta Lucene 1.4.3" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks XSS in Apache Jakarta Lucene.");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit ( 0 );

function check_dir(path)
{
 local_var req, r;
 global_var port;

 r = http_send_recv3(port: port, method: 'GET', item: strcat(path, '/results.jsp?query="><script>foo</script>"'));
 if (isnull(r)) exit(0);

 if ( "<script>foo</script>" >< r[2])
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check_dir(path:dir);
}
 
