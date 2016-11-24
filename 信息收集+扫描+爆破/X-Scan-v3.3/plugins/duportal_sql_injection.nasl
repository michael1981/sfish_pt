#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18120);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-1224", "CVE-2005-1236");
  script_bugtraq_id(13285, 13288);
  script_xref(name:"OSVDB", value:"15832");
  script_xref(name:"OSVDB", value:"15833");
  script_xref(name:"OSVDB", value:"15834");
  script_xref(name:"OSVDB", value:"15835");
  script_xref(name:"OSVDB", value:"15836");
  script_xref(name:"OSVDB", value:"15837");
  script_xref(name:"OSVDB", value:"15852");
  script_xref(name:"OSVDB", value:"15853");
  script_xref(name:"OSVDB", value:"15854");
  script_xref(name:"OSVDB", value:"15855");

  script_name(english:"DUPortal/DUPortal Pro Multiple Scripts SQL Injection (1)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an ASP application that is affected
by multiple SQL injection flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DUPortal, a content management system
written in ASP. 

The remote version of this software is vulnerable to several SQL
injection vulnerabiliies in files 'details.asp', 'search.asp',
'default.asp' , 'cat.asp' and more. 

With a specially-crafted URL, an attacker can exploit this flaw to
modify database queries, potentially even uncovering user passwords
for the application." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2006-04/0554.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
  summary["english"] = "Checks for SQL injection vulnerability in DUPortal";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

if(get_port_state(port))
{
   foreach dir (cgi_dirs())
   {
  	r1 = http_send_recv3(port:port, method: "GET", item:dir + "/detail.asp?nChannel='1");
	if (isnull(r1)) exit(0);
  	r2 = http_send_recv3(port:port, method: "GET", item:dir + "/home/search.asp?nChannel='1");
	if (isnull(r2)) exit(0);
  	if ( ( "Microsoft OLE DB Provider for ODBC Drivers error '80040e14'" >< r1[2] ) ||
             ( "Microsoft OLE DB Provider for ODBC Drivers error '80040e14'" >< r2[2] ) )
  	{
    		security_hole(port);
		set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	 	exit(0);
  	}
   }
}
