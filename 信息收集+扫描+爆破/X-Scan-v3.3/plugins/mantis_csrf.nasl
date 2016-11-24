#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32324);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-2276");
  script_xref(name:"milw0rm", value:"5657");
  script_xref(name:"OSVDB", value:"45214");
  script_xref(name:"Secunia", value:"30270");

  script_name(english:"Mantis manage_user_create.php CSRF New User Creation");
  script_summary(english:"Sends a GET request for manage_user_create.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple cross-site request forgery vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Mantis Bug Tracker installed on the remote host does
not verify the validity of HTTP requests before performing various
administrative actions.  If a remote attacker can trick a logged-in
administrator into viewing a specially-crafted page, he can leverage
this issue to launch cross-site request forgery attacks against the
affected application, such as creating additional users with
administrator privileges. 

Note that the application also is reportedly affected by other issues,
including one that allows remote code execution provided an attacker
has administrator privileges, although Nessus did not explicitly test
for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=8995" );
 script_set_attribute(attribute:"see_also", value:"http://www.attrition.org/pipermail/vim/2008-May/001980.html" );
 script_set_attribute(attribute:"see_also", value:"http://mantisbt.svn.sourceforge.net/viewvc/mantisbt?view=rev&revision=5132" );
 script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/blog/?p=19" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mantis 1.2.0a1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Send a GET request for manage_user_create.php.
  req = http_get(item:string(dir, "/manage_user_create.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if we get redirected to the login form as the
  # patch instead results in an application error unless a POST
  # request was sent.
  headers = res - strstr(res, '\r\n\r\n');
  if (egrep(pattern:"^Location: +login_page\.php.+manage_user_create\.php", string:headers))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
