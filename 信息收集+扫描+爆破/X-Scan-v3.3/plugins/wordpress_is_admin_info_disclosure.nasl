#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29745);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(26885);
  script_xref(name:"OSVDB", value:"39518");
  script_xref(name:"Secunia", value:"28130");

  script_name(english:"WordPress query.php is_admin() Function Information Disclosure");
  script_summary(english:"Sends a request with 'wp-admin/' in the query string");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The version of WordPress on the remote host does not properly check
for administrative credentials in the 'is_admin()' function in
'wp-includes/query.php'.  Using a specially-crafted URL that contains
the string 'wp-admin/', an attacker may be able to leverage this issue
to view posts for which the status is classified as 'future', 'draft',
or 'pending', which would otherwise be available only to authenticated
users." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485160/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://trac.wordpress.org/ticket/5487" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw.
  req = http_get(
    item:string(dir, "/index.php/nessus-wp-admin/"), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # The fix results in a redirect so there's a problem if we get posts instead.
  if ('<div class="post' >< res && 'id="post-' >< res)
  {
    security_warning(port);
    exit(0);
  }
}
