#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

if(description)
{
 script_id(11149);
 script_version ("$Revision: 1.16 $");
 
 script_name(english: "HTTP login page");
 
 script_set_attribute(attribute:"synopsis", value:
"HTTP form based authentication." );
 script_set_attribute(attribute:"description", value:
"This script logs onto a web server through a login page and
stores the authentication / session cookie." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:
"None" );

script_end_attributes();

 script_summary(english: "Log through HTTP page");
 script_category(ACT_GATHER_INFO);	# Has to run after find_service
 script_copyright(english: "This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "Settings");

 # We first visit this page to get a cookie, just in case
 script_add_preference(name:"Login page :", type: "entry", value: "/");
 # Then we submit the username & password to the right form
 script_add_preference(name:"Login form :", type: "entry", value: "");
 # Here, we allow some kind of variable substitution. 
 script_add_preference(name:"Login form fields :", type: "entry", 
	value:"user=%USER%&pass=%PASS%");
 script_dependencie("find_service1.nasl", "httpver.nasl", "logins.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# The script code starts here

http_login = get_kb_item("http/login");
http_pass = get_kb_item("http/password");
http_login_form = script_get_preference("Login form :");
http_login_page = script_get_preference("Login page :");
http_login_fields = script_get_preference("Login form fields :");

if (! http_login_form) exit(0);
if (! http_login_fields) exit(0);

http_set_read_timeout(2 * get_read_timeout());	# safer

if (http_login)
{
  http_login_fields = ereg_replace(string: http_login_fields,
	pattern: "%USER%", replace: http_login);
}
if (http_pass)
{
  http_login_fields = ereg_replace(string: http_login_fields,
	pattern: "%PASS%", replace: http_pass);
}

port = get_http_port(default:80, embedded: TRUE);

enable_cookiejar();

h = NULL;
if (http_login_page)
{
  r = http_send_recv3(port: port, item: http_login_page, method: 'GET');

  trp = get_port_transport(port);

  if (trp > ENCAPS_IP)
    referer = "https://";
  else
    referer = "http://";

  referer = strcat(referer, get_host_name());
  if ((trp == 1 && port != 80) || (trp > 1 && port != 443))
    referer = strcat(referer, ":", port);
  if (http_login_page[0] != '/') referer = strcat(referer, '/');
  referer = strcat(referer, http_login_page);
  h["Referer"] = referer;
}

h["Content-Type"] = "application/x-www-form-urlencoded";
r = http_send_recv3( port: port, method: 'POST', 
    		     add_headers: h,
		     follow_redirect: 2,
    		     item: http_login_form, data: http_login_fields);
if (isnull(r))
{
  debug_print("Broken connection on port ", port, " after POST ", http_login_form);
  exit(0);
}
# Failed - permission denied or bad gateway or whatever
if (r[0] =~ "^HTTP/[019.]+ +[45][0-9][0-9] ")
{
  debug_print("Permission denied: code=", r[0]);
  exit(0);
}

# All other codes are considered as OK. We might get a 30x code!

store_cookiejar("FormAuth");

# Compatibility with old code
rq = http_mk_get_req(item: "/", port: port);
cookies = rq["Cookie"];
if (cookies)
  set_kb_item(name: string("/tmp/http/auth/", port), value: cookies+'\r\n');
else
  debug_print("No cookie is set. Authentication failed.\n");
