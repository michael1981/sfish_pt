#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(18539);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2033", "CVE-2005-2034");
  script_bugtraq_id(14000, 14002);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"17401");

  name["english"] = "i-Gallery <= 3.3 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is susceptible
to multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running i-Gallery, a web-based photo gallery from
Blue-Collar Productions. 

The installed version of i-Gallery fails to sanitize user-supplied
input before using it as a folder name in several scripts.  An
unauthenticated attacker can exploit this flaw to access files and
folders outside i-Gallery's main gallery folder and to conduct
cross-site scripting attacks against visitors to the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/402880/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in i-Gallery <= 3.3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the directory traversal flaw.
  req = http_get(item:string(dir, "/folderview.asp?folder=.."), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we can see anything in the parent directory.
  if (
    egrep(
      string:res, 
      # nb: 'i' is for the filename, 'f' the folder.
      pattern:"viewphoto\.asp?i=[^&]+&f=\.\."
    )
  ) { 
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
