#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16154);
 script_cve_id("CVE-2005-0217");
 script_bugtraq_id(12205);
 script_xref(name:"OSVDB", value:"12817");
 script_version("$Revision: 1.8 $");
 script_name(english:"Invision Community Blog Module eid Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is a hosting an application that is affected
by a SQL injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Invision Community Blog, a
weblog utility.

There is a flaw in the remote software which may allow anyone to 
inject arbitrary SQL commands through the 'index.php' script, which
may in turn be used to gain administrative access on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-01/0078.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2679d827" );
 script_set_attribute(attribute:"solution", value:
"Patches are available from the above reference." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie( "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

function check(dir)
{
  local_var res;

  res = http_send_recv3(method:"GET", item:string(dir, "/index.php?automodule=blog&blogid=1&cmd=showentry&eid=1'"), port:port);
  if (isnull(res)) exit(1, "The remote web server did not respond.");

  if("SELECT * FROM ibf_blog_entries WHERE blog_id=1 and entry_id" >< res[2] )
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
