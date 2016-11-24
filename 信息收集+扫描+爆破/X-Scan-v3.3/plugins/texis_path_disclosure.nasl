#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11401);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2002-0266");
 script_bugtraq_id(4035);
 script_xref(name:"OSVDB", value:"4313");

 script_name(english:"Thunderstone Software Texis Nonexistent File Request Path Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote CGI 'texis.exe' (on Windows) or 'texis' (on Unix) 
discloses the physical path of the remote web server when 
requested a nonexistent file." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for texis.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
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

foreach d ( cgi_dirs() )
{
  res = http_send_recv3(method:"GET", item:string(d, "/texis.exe/nessus"), port:port);
  if (isnull(res)) exit (0);
  if(egrep(pattern:"[a-z]:\\.*\\nessus", string:res[2])) 
  {
    security_warning(port);
    exit(0);
  }
}
