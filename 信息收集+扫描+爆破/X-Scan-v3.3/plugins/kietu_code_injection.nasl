#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Cc: vulnwatch@vulnwatch.org
# Subject: [VulnWatch] Kietu ( PHP )

include("compat.inc");

if(description)
{
 script_id(11328);
 script_version ("$Revision: 1.14 $");

 script_bugtraq_id(9499);
 script_xref(name:"OSVDB", value:"3763");

 script_name(english:"Kietu index.php Remote File Inclusion");
 script_summary(english:"Checks for the presence of hit.php");

 script_set_attribute(
  attribute:"synopsis",
  value:
"The remote web server hosts a PHP application that is affected by a
remote file inclusion vulnerability."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"The version of the Kietu web statistics application hosted on the
remote web server fails to sanitize user-supplied input to the
'url_hit' parameter of the 'index.php' script before using it to
include PHP code.  Regardless of PHP's 'register_globals' setting, an
unauthenticated attacker can exploit this issue to view arbitrary
files or possibly to execute arbitrary PHP code, possibly taken from
third-party hosts."
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2003-02/0208.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Contact the vendor for a fix."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2003/02/15"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2003/03/07"
 );
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
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

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var r, w;

 w = http_send_recv3(item:string(loc, "/index.php?kietu[url_hit]=http://xxxxxxxx/"),
 		method:"GET", port:port);			
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if(egrep(pattern:".*http://xxxxxxxx/config\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


dirs = make_list(cgi_dirs(), "/");


foreach dir (dirs)
{
 check(loc:dir);
}
