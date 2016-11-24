#
# (C) Tenable Network Security, Inc.
#
# Ref:
#
# From: Seth Woolley <seth@tautology.org>
# To: bugtraq@securityfocus.com
# Cc: full-disclosure@lists.netsys.com
# Subject: Cafelog WordPress / b2 SQL injection vulnerabilities discovered and
#   fixed in CVS


include("compat.inc");


if(description)
{
 script_id(11866);
 
 script_version ("$Revision: 1.15 $");

 script_bugtraq_id(8756);
 script_xref(name:"OSVDB", value:"4609");

 script_name(english:"WordPress blog.header.php Multiple Parameter SQL Injection");
 script_summary(english:"Checks for the presence of cafe wordpress");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote web server is hosting a blog with multiple SQL injection\n",
     "vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of Cafe WordPress running on the remote host has multiple\n",
     "SQL injection vulnerabilities.  An attacker could exploit these flaws\n",
     "to read/modify information in the database, and gain further access\n",
     "on this host."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q4/0109.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to version 0.72 RC1 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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
if(!can_host_php(port:port)) exit(0);


function check(loc)
{
 local_var url, req, r;
 global_var port;

 url = string(loc, "/index.php?cat='");
 r = http_send_recv3(method:"GET", item:url, port:port);
 if( isnull(r) )exit(0);

 if(egrep(pattern:"SQL.*post_date <=", string:r))
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}



dirs = make_list(cgi_dirs());


foreach dir (dirs)
{
 check(loc:dir);
}
