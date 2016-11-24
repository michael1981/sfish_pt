#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(15403);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2004-1566", "CVE-2004-1567");
  script_bugtraq_id(11284);
  script_xref(name:"OSVDB", value:"10452");
  script_xref(name:"OSVDB", value:"10453");

  script_name(english:"Silent-Storm Portal Multiple Input Validation Vulnerabilities");
  script_summary(english:"Checks for vulnerabilities in Silent-Storm Portal");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is affected by\n",
      "multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running Silent-Storm, a web-based forum management\n",
      "software written in PHP.\n",
      "\n",
      "There are multiple input validation flaws in the remote version of\n",
      "this software :\n",
      "\n",
      "  - There is a cross-site scripting vulnerability involving\n",
      "    the 'module' parameter of the 'index.php' script.\n",
      "\n",
      "  - The application fails to sanitize the 'mail' parameter\n",
      "    to the 'profile.php' script, which could be abused to\n",
      "    inject arbitrary data into the 'users.dat' database\n",
      "    file and, for example, gain administrative access to\n",
      "    the application."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0440.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
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

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);


function check(dir)
{
  local_var buf, req;
  req = http_get(item:dir + "/index.php?module=<script>foo</script>", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(isnull(buf))exit(0);

  if("<script>foo</script>" >< buf && "copyright silent-storm.co.uk" >< buf )
  	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
	}
 
 
 return(0);
}


foreach dir (cgi_dirs()) 
 {
  check( dir : dir );
 }
