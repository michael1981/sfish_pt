#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Javier Ubilla and Ariel
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (5/20/09)


include("compat.inc");

if (description)
{
 script_id(14257);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-1711");
 script_bugtraq_id(10884);
 script_xref(name:"OSVDB", value:"8383");

 script_name(english:"Moodle post.php reply Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Moodle on the remote host contains a flaw that allows a
remote cross site scripting attack because the application does not
validate the 'reply' variable upon submission to the 'post.php'
script. 

This could allow a user to create a specially crafted URL that would 
execute arbitrary code in a user's browser within the trust 
relationship between the browser and the server, leading to a loss of
integrity." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0093.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Moodle 1.4 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determines if Moodle is vulnerable to post.php XSS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_dependencie("moodle_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))
	exit(0);
if(!can_host_php(port:port))
	exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  req = http_get(item:string(dir, "/post.php?reply=<script>document.write('Nessus plugin to detect post.php flaw');</script>"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(res == NULL ) 
    exit(0);
 
  if (ereg(pattern:"Nessus plugin to detect post.php flaw", string:res ))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
