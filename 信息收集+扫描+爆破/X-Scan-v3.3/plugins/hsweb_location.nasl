#
# (C) Tenable Network Security, Inc.
#

# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
 script_id(10606);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2001-0200");
 script_bugtraq_id(2336);
 script_xref(name:"OSVDB", value:"502");

 script_name(english:"HSWeb HTTP Server /cgi Directory Request Path Disclosure");
 script_summary(english:"Retrieve the real path using /cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to request the physical location of the remote web root
by requesting the folder '/cgi'. An attacker can exploit this flaw to
gain more knowledge about this host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-02/0052.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

res = http_send_recv3(method:"GET", item:"/cgi", port:port);
if (isnull(res)) exit(1, "The Web server did not respond");

if("Directory listing of" >< res[2])
{
  security_warning(port:port);
  exit(0);
}

