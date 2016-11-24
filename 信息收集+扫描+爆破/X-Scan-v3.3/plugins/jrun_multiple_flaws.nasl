#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14810);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2004-0646", "CVE-2004-0928", "CVE-2004-1477", "CVE-2004-1478", "CVE-2004-2182");
 script_bugtraq_id(11245, 11331, 11411, 11413, 11414);
 script_xref(name:"OSVDB", value:"10238");
 script_xref(name:"OSVDB", value:"10239");
 script_xref(name:"OSVDB", value:"10240");
 script_xref(name:"OSVDB", value:"10546");
 script_xref(name:"OSVDB", value:"19753");

 script_name(english:"JRun Multiple Vulnerabilities (OF, XSS, ID, Hijacking)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running JRun, a J2EE application server running on
top of IIS or Apache.  There are multiple flaws in the remote version
of this software :

 - The JSESSIONID variable is not implemented securely. An attacker may
   use this flaw to guess the session id number of other users. Only
   JRun 4.0 is affected.

 - There is a code disclosure issue which may allow an attacker to obtain
   the contents of a .cfm file by appending ';.cfm' to the file name.
   Only the Microsoft IIS connector and JRun 4.0 are affected.

 - There is a buffer overflow vulnerability if the server connector is 
   configured in 'verbose' mode. An attacker may exploit this flaw to 
   execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.acrossecurity.com/papers/session_fixation.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?type=vulnerabilities&id=145" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?type=vulnerabilities&id=148" );
 script_set_attribute(attribute:"see_also", value:"http://www.macromedia.com/devnet/security/security_zone/mpsb04-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.macromedia.com/devnet/security/security_zone/mpsb04-09.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch / updater referenced in the vendor
advisories above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"downloads the source of CFM scripts");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "webmirror.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

function check(file, port)
{
  local_var r, req;

  file = str_replace(find:".cfm", replace:";.cfm", string:file);
  req = http_get(item:file, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( ! r ) exit(0);
  r = tolower(r);
  if ( egrep(pattern:"< *(cfinclude|cfset|cfparam)", string:r) )
	{
  	security_warning(port);
	return(1);
	}
 return(0);
}

port = get_http_port(default:80);
banner = get_http_banner(port:port);

if( banner && "JRun" >< banner )
{
 if(check(file:"/index.cfm", port:port))exit(0);
 files = get_kb_list(string("www/", port, "/content/extensions/cfm"));
 if(isnull(files))exit(0);
 files = make_list(files);
 check(file:files[0], port:port);
}
