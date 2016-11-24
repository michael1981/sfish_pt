#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(14828);
 script_cve_id("CVE-2004-1555");
 script_xref(name:"OSVDB", value:"10336");
 script_xref(name:"OSVDB", value:"10337");
 script_xref(name:"OSVDB", value:"10338");
 script_xref(name:"OSVDB", value:"10339");
 script_xref(name:"Secunia", value:"12658");
 script_bugtraq_id(11250);
 script_version("$Revision: 1.11 $");
 script_name(english:"BroadBoard Multiple Script SQL Injection");
 script_summary(english:"SQL Injection");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote web server is hosting an application written in ASP with\n",
     "multiple SQL injection vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be running BroadBoard, an ASP script\n",
     "designed to manage a web-based bulletin-board system.\n\n",
     "There is a flaw in the remote software which may allow a remote\n",
     "attacker to inject arbitrary SQL commands, which may in turn be used\n",
     "to gain administrative access on the remote host."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-09/0963.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BroadBoard."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (! can_host_asp(port:port)) exit(0);


function check(dir)
{
  local_var buf, r;
  r = http_send_recv3(method:"GET", item:dir + "/profile.asp?handle=foo'", port:port);
  if (isnull(r)) exit(0);
  buf = strcat(r[0], r[1], '\r\n', r[2]);

  if("error '80040e14'" >< buf &&
     "'tblUsers.UserHandle='foo'''" >< buf )
  	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 
 
 return(0);
}

foreach dir (cgi_dirs()) 
 {
  check(dir:dir);
 }
