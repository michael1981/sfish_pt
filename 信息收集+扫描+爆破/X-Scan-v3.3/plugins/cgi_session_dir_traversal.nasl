#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33532);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(30267);
  script_xref(name:"Secunia", value:"31117");
  script_xref(name:"OSVDB", value:"47496");

  script_name(english:"CGI::Session File Driver CGISESSID Cookie Traversal Authentication Bypass");
  script_summary(english:"Sends a session cookie with directory traversal sequences");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PERL module that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using the CGI::Session PERL module to
manage file-based sessions. 

The version of this module installed on the remote host fails to
properly sanitize input to the session cookie of directory traversal
sequences.  An unauthenticated remote attacker may be able to leverage
this issue on a Windows system to bypass session-based controls." );
 script_set_attribute(attribute:"see_also", value:"http://vuln.sg/cgisession433-en.html" );
 script_set_attribute(attribute:"see_also", value:"http://vuln.sg/fswiki362session-en.html" );
 script_set_attribute(attribute:"see_also", value:"http://search.cpan.org/src/MARKSTOS/CGI-Session-4.34/Changes" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CGI::Session version 4.34 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "twiki_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


# The issue only affects Windows hosts.
os = get_kb_item("Host/OS/smb");
if (!os || "Windows" >!< os) exit(0);


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

init_cookiejar();
# Pattern to match session ids associated with CGI::Session.
#
# nb: TWiki uses CGI::SESSION and names the cookie "TWIKISID".
sid_pat = "^Set-Cookie: *(CGISESSID|TWIKISID)=([0-9a-hA-H]{32})(;|$)";


# Identify URLs to scan.
urls = make_list();
# - directories turned up by webmirror.
dirs = cgi_dirs();
if (!isnull(dirs))
{
  foreach dir (make_list(dirs))
    urls = make_list(urls, dir+'/');
}
# - apps that we detect and that use the module.
foreach app (make_list("twiki"))
{
  install = get_kb_item(string("www/", port, "/", app));
  if (!isnull(install))
  {
    matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
    if (!isnull(matches))
    {
      dir = matches[2];

      add = TRUE;
      foreach d (dirs)
      {
        if (d == dir)
        {
          add = FALSE;
          break;
        }
      }
      if (add)
      {
        if ("twiki" == app) urls = make_list(dir+'/view/', urls);
        else urls = make_list(dir+'/', urls);
      }
    }
  }
}
# - known PERL scripts if thorough tests are enabled (since individual
#   PERL scripts may or may not use the module).
if (thorough_tests)
{
  foreach ext (make_list("pl", "cgi"))
  {
    cgis = get_kb_list(string("www/", port, "/content/extensions/", ext));
    if (cgis)
    {
      foreach cgi (make_list(cgis))
        urls = make_list(urls, cgi);
    }
  }
}


# Loop through various URLs.
info = "";

foreach url (list_uniq(urls))
{
  # Get a session id.
  r = http_send_recv3(port: port, method: 'GET', item: url);
  foreach cookie_name (make_list("CGISESSID", "TWIKISID"))
  {
    cookie_value = get_http_cookie(name: cookie_name);
    if (strlen(cookie_value) > 0) break;
    else cookie_name = NULL;
  }
  
    if (cookie_name && cookie_value)
    {
      # Try to exploit the issue.
      set_http_cookie(name: cookie_name, value: "=/../cgisess_"+cookie_value);
      r = http_send_recv3(port:port, method: 'GET', item: url);
      if (isnull(r)) exit(0);
      v = get_http_cookie(name: cookie_name);
      if (v == cookie_value)
      {
        info += '  ' + url + ' (via the ' + cookie_name + ' cookie)\n';
        if (!thorough_checks) break;
      }
    }
}


# Report if any vulnerable instances were discovered.
if (info)
{
  if (report_verbosity)
  {
    if (max_index(split(info)) > 1) s = "s appear";
    else s = " appears";

    report = string(
      "The following URL", s, " to be affected :\n",
      "\n",
      info
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
