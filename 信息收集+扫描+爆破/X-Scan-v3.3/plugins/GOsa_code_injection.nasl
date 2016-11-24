#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: Karol Wiesek <appelast@bsquad.sm.pl>
# To: bugtraq@securityfocus.com
# Subject: GOnicus System Administrator php injection
# Message-ID: <20030224164419.GA13904@bsquad.sm.pl>


include("compat.inc");

if(description)
{
 script_id(11275);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2003-1412");
 script_bugtraq_id(6922);
 script_xref(name:"OSVDB", value:"51195");
 script_xref(name:"OSVDB", value:"51196");
 script_xref(name:"OSVDB", value:"51197");
 script_xref(name:"OSVDB", value:"51198");
 script_xref(name:"OSVDB", value:"51199");
 script_xref(name:"OSVDB", value:"51200");

 script_name(english:"GOsa Multiple Script plugin Parameter Remote File Inclusion");
 script_summary(english:"Checks for the presence of remotehtmlview.php");

 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote web server contains a PHP application that is affected by\n",
   "multiple remote file include vulnerabilities."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote web server is hosting GOnicus System Administrator (GOsa),\n",
   "a PHP-based administration tool for managing accounts and systems in\n",
   "LDAP databases.\n",
   "\n",
   "The version of GOsa installed on the remote host fails to sanitize\n",
   "user input to the 'plugin' parameter of several scripts before using\n",
   "it to include PHP code.\n",
   "\n",
   "An unauthenticated remote attacker can leverage these issues to view\n",
   "arbitrary files or possibly to execute arbitrary PHP code, possibly\n",
   "taken from third-party hosts.\n",
   "\n",
   "Note that GOsa reportedly doesn't support disabling PHP's\n",
   "'register_globals' setting."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q1/0839.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Unknown at this time."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2003/02/23"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2003/02/27"
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

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "Web server does not support PHP scripts.");



function check(loc)
{
 local_var r;
 r = http_send_recv3(method:"GET",
     item:string(loc, "/include/help.php?base=http://xxxxxxxx"),
 		port:port);	
 if (isnull(r)) exit(1, "The web server failed to respond.");

 if(egrep(pattern:".*http://xxxxxxxx/include/common\.inc", string:r[2]))
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
