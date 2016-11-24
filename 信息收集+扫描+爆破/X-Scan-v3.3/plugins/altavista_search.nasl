#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10015);
 script_bugtraq_id(896);
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-2000-0039");
 script_xref(name:"OSVDB", value:"15");
 script_name(english:"AltaVista Intranet Search CGI query Traversal Arbitrary File Access");
 script_summary(english:"Checks if query?mss=... reads arbitrary files");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a CGI script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to read the content of any files on the remote 
host (such as your configuration files or other sensitive data) 
by using the Altavista Intranet Search service, and performing 
the request:" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q4/0497.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q4/0518.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-01/0011.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-01/0119.html" );
 script_set_attribute(attribute:"see_also", value:"http://doc.altavista.com/business_solutions/search_products/free_downloads/search_intranet.shtml" );
 script_set_attribute(attribute:"solution", value:
"The vendor has released a patch that reportedly fixes this issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
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
item = "/cgi-bin/query?mss=%2e%2e/config";
r = http_send_recv3(method:"GET", item:item, port:port);
if (isnull(r)) exit(0);
result = strcat(r[0], r[1], '\r\n', r[2]);
if("MGMT_PW" >< result){
	security_warning(port);
	exit(0);
	}
