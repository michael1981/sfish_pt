#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15968);
 script_cve_id("CVE-2004-1401");
 script_bugtraq_id(11933);
 script_xref(name:"OSVDB", value:"12548");
 script_xref(name:"Secunia", value:"13470");
 script_version("$Revision: 1.10 $");
 script_name(english:"ASP-Rider verify.asp username Parameter SQL Injection");
 script_summary(english:"SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is susceptible to a
remote SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running ASP-Rider, a set of ASP scripts
designed to maintain a blog.

There is a flaw in the remote software which may allow anyone to
inject arbitrary SQL commands, which may in turn be used to gain
administrative access on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/384421/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  r = http_send_recv3(method:"GET", port: port, item: dir + "/verify.asp?username='");
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);
  if ("80040e14" >< res &&
      "'username=''''" ><  res )
  {
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
 }
