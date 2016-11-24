#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35661);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2008-3663");
  script_bugtraq_id(31321);
  script_xref(name:"OSVDB", value:"49095");

  script_name(english:"SquirrelMail HTTPS Session Cookie Secure Flag Weakness");
  script_summary(english:"Looks for 'secure' flag in Squirrelmail cookie");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote web server contains a PHP application that handles session\n",
      "cookies insecurely."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of SquirrelMail installed on the remote host does not set\n",
      "the 'secure' flag for session cookies established when communicating\n",
      "over SSL / TLS.  This could lead to disclosure of those cookies if a\n",
      "user issues a request to a host in the same domain over HTTP (as\n",
      "opposed to HTTPS)."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://int21.de/cve/CVE-2008-3663-squirrelmail.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/496601/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.squirrelmail.org/security/issue/2008-09-28"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to SquirrelMail version 1.4.16 or later and ensure that the\n",
      "'only_secure_cookies' configuration option is set to 'true'."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("squirrelmail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:443);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# NB: we only care about TLS / SSL.
encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && (encaps < ENCAPS_SSLv2 || encaps > ENCAPS_TLSv1)) exit(0);


cookie_name = "SQMSESSID";


# Test an install.
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  # Request the login page and check for the 'secure' flag.
  dir = matches[2];
  url = string(dir, "/src/login.php");

  init_cookiejar();
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (res == NULL) exit(0);

  insecure = NULL;
  sqm_cookies = get_http_cookie_keys(name_re:cookie_name);
  if (!isnull(sqm_cookies) && max_index(sqm_cookies))
  {
    foreach key (sqm_cookies)
    {
      cookie = get_http_cookie_from_key(key);
      if (!cookie["secure"])
      {
        insecure = cookie["value"];
        break;
      }
    }
  }

  # There's a problem if it wasn't set.
  if (!isnull(insecure))
  {
    if (report_verbosity)
    {
      cookie_hdrs = "";
      foreach line (split(res[1]))
        if (line =~ "^Set-Cookie" && string(cookie_name, "=", insecure) >< line) cookie_hdrs += '  ' + line;

      if (max_index(split(cookie_hdrs)) > 1) s = "s";
      else s = "";

      report = string(
        "\n",
        "Requesting SquirrelMail's login page produced a response with the\n",
        "following insecure Cookie header", s, " :\n",
        "\n",
        cookie_hdrs
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
