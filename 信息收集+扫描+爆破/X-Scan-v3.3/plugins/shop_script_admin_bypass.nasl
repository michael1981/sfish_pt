#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26065);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-4932");
  script_bugtraq_id(25695);
  script_xref(name:"OSVDB", value:"40149");

  script_name(english:"Shop-Script admin.php Admin Panel Security Bypass");
  script_summary(english:"Tries to retrieve configuration settings");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Shop-Script, a shopping cart software
application written in PHP. 

The version of Shop-Script installed on the remote host fails to halt
execution of the script 'admin.php' if an attacker is not
authenticated, which allows him to effectively bypass the
authentication check and gain control of the application. 

Note that the application is also likely affected by another
vulnerability that allows for arbitrary code execution by means of
specially-crafted changes to the application's Appearance
configuration settings, although Nessus has not checked for this. 

By leveraging these two issues, a unauthenticated remote attacker is
probably able to execute arbitrary code on the affected host subject
to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.milw0rm.com/exploits/4419" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/shopscript", "/shop", "/store", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to retrieve the general configuration settings.
  req = http_get(
    item:string(dir, "/admin.php?dpt=conf&sub=general"), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (isnull(res)) exit(0);

  # There's a problem if...
  if (
    # we gain access to the main form and...
    '<form action="admin.php' >< res && '<input type=hidden name=save_general' >< res &&
    # there's a redirection to the access_admin.php script
    egrep(pattern:"^Location: +access_admin\.php", string:res)
  )
  {
    security_hole(port);
    exit(0);
  }
}
