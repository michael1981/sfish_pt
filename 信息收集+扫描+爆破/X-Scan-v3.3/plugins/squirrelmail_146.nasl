#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(20970);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-0188", "CVE-2006-0195", "CVE-2006-0377");
  script_bugtraq_id(16756);

  script_name(english:"SquirrelMail < 1.4.6 Multiple Vulnerabilities");
  script_summary(english:"Checks for IMAP command injection in SquirrelMail");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote webmail application is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The installed version of SquirrelMail fails to sanitize user-supplied
input to mailbox names before passing them to an IMAP server.  An
unauthenticated attacker may be able to leverage this issue to launch
attacks against the underlying IMAP server or against a user's
mailboxes by tricking him into clicking on a specially-formatted link
in an email message. 

There are also reportedly several possible cross-site scripting flaws
that could be exploited to injection arbitrary HTML and script code
into a user's browser." );
 script_set_attribute(attribute:"see_also", value:"http://www.squirrelmail.org/security/issue/2006-02-01" );
 script_set_attribute(attribute:"see_also", value:"http://www.squirrelmail.org/security/issue/2006-02-10" );
 script_set_attribute(attribute:"see_also", value:"http://www.squirrelmail.org/security/issue/2006-02-15" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SquirrelMail 1.4.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("squirrelmail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("imap/login", "imap/password");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# nb: the vulnerabilities can't be exploited without being authenticated.
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) exit(0);


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  init_cookiejar();
  # Try to login.
  r = http_send_recv3(method: "GET", item:string(dir, "/src/login.php"), port:port);
  if (isnull(r)) exit(0);

  # - first grab the session cookie.
  sid = get_http_cookie(name: "SQMSESSID");
  if (isnull(sid)) {
    debug_print("can't get session cookie!");
    exit(1);
  }
  # - now send the username / password.
  postdata = string(
    "login_username=", user, "&",
    "secretkey=", pass, "&",
    "js_autodetect_results=0&",
    "just_logged_in=1"
  );
  r = http_send_recv3(method: "POST", item: strcat(dir, "/src/redirect.php"), 
    port: port, data: postdata,
 add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  if (isnull(r)) exit(0);
  if (get_http_cookie(name: "SQMSESSID") == "deleted") {
    debug_print("user/password incorrect!");
    exit(1);
  }

  # - and get the secret key.
  key = get_http_cookie(name: "key");
  if (isnull(key)) {
    debug_print("can't get secret key!");
    exit(1);
  }

  # Finally, try to exploit the IMAP injection flaw.
  r = http_send_recv3(method: "GET", 
    item:string(
      dir, "/src/right_main.php?",
      "PG_SHOWALL=0&",
      "sort=0&",
      "startMessage=1&",
      # nb: this is just a corrupted mailbox name, but since the fix
      #     strips out CR/LFs, this will suffice as a check.
      "mailbox=INBOX\\r\\n", SCRIPT_NAME
    ), 
    port:port
  );
  # There's a problem if we see an error with the corrupted mailbox name.
  if (string("SELECT &quot;INBOX\\r\\n", SCRIPT_NAME) >< r[2]) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }

  # Be nice and sign out.
  r = http_send_recv3(method: "GET", item:string(dir, "/src/signout.php"), port:port);
}
