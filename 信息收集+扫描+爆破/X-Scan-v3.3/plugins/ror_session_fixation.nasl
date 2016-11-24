#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(28333);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-5380", "CVE-2007-6077");
  script_bugtraq_id(26096, 26598);
  script_xref(name:"OSVDB", value:"39193");
  script_xref(name:"OSVDB", value:"40718");

  script_name(english:"Ruby on Rails Multiple Method Session Fixation");
  script_summary(english:"Tries to pass a session cookie via URL"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a session fixation vulnerability." );
 script_set_attribute(attribute:"description", value:
"The web server on the remote host appears to be a version of Ruby on
Rails that supports URL-based sessions.  An unauthenticated remote
attacker may be able to leverage this issue to obtain an authenticated
session. 

Note that Ruby on Rails version 1.2.4 was initially supposed to
address this issue, but its session fixation logic only works for the
first request, when CgiRequest is first instantiated." );
 script_set_attribute(attribute:"see_also", value:"http://weblog.rubyonrails.org/2007/10/5/rails-1-2-4-maintenance-release" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f5b72e6" );
 script_set_attribute(attribute:"see_also", value:"http://dev.rubyonrails.org/ticket/10048" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1eeea9de" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Ruby on Rails version 1.2.6 or later and make sure
'config.action_controller.session_options[:cookie_only]' is set to
'true' in the 'config/environment.rb' file." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (get_kb_item("www/no404/" + port)) exit(0);

# Request a nonexistent page.
foreach dir (cgi_dirs())
{
  clear_cookiejar();
  url = string(dir, "/", unixtime(), "-", SCRIPT_NAME);

  r = http_send_recv3(method: 'GET', item:url, port:port);
  if (isnull(r)) exit(0);

  # Look for a session cookie.
  cookies = get_http_cookies_names();
  if (! isnull(cookies))
  {
    # Copy the cookie jar, we are going to clear it 
    cookie_val = NULL;
    foreach cookie_name (cookies)
      cookie_val[cookie_name] = get_http_cookie(name: cookie_name, path: url);
    
    foreach cookie_name (cookies)
    {
         # If either...
          if (
            # we're paranoid and the cookie name is not PHP's default or...
            (
              report_paranoia > 1 && 
              "PHPSESSID" >!< cookie_name && 
              "ASPSESSIONID" >!< cookie_name
            ) ||
            # it looks like one commonly used by RoR
            cookie_name =~ "_(sess|session)_id$"
          )
          {
	    clear_cookiejar();
	    val = cookie_val[cookie_name];
            # Try to pass the cookie in as a parameter.
            r = http_send_recv3(method: "GET", 
              item:string(url, "?", cookie_name, "=", val), 
              port:port
            );
            if (isnull(r)) exit(0);

            # There's a problem if we get the same cookie back.
	    val2 = get_http_cookie(name: cookie_name, path: url);
            if (val == val2)
            {
              security_warning(port);
              exit(0);
            }
          }
        }
      }
}
