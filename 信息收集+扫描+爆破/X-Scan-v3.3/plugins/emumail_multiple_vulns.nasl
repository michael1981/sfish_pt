#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");


if(description)
{
 script_id(12095);
 script_cve_id("CVE-2004-2334", "CVE-2004-2385");
 script_bugtraq_id(9861);
 script_xref(name:"OSVDB", value:"4203");
 script_xref(name:"OSVDB", value:"4204");
 script_xref(name:"OSVDB", value:"4972");
 
 script_version("$Revision: 1.11 $");

 script_name(english:"Emumail WebMail Multiple Remote Vulnerabilities (XSS, Disc)");
 script_summary(english:"version test for Emumail");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A webmail application running on the remote host has multiple\n",
     "vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to its version number, the remote host is running a\n",
     "vulnerable version of EMUMAIL WebMail.\n\n",
     "There are several flaws in this version, ranging from information\n",
     "disclosure to cross-site scripting vulnerabilties, which may allow an\n",
     "attacker to trick a logged in user into providing access to this system."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
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


function check(dir, port)
{
  local_var req, res;

  req = string(dir, "/emumail.fcgi");
  res = http_send_recv3(method:"GET", item:req, port:port);
  if (isnull(res)) exit(0);

  if ("Powered by EMU Webmail" >< res[2])
   {
    if ( egrep(pattern:"(Powered by|with) EMU Webmail ([0-4]\.|5\.([01]\.|2\.[0-7][^0-9]))", string:res[2]) ) {
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
    }
   }
 return(0);
}


#
# Execution begins here
#
port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 check(dir:dir, port:port);
}
