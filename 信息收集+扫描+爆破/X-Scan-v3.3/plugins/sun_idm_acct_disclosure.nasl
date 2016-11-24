#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38198);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2009-1075", "CVE-2009-1076");
  script_bugtraq_id(34191);
  script_xref(name:"OSVDB", value:"53162");
  script_xref(name:"OSVDB", value:"53163");
  script_xref(name:"Secunia", value:"34380");

  script_name(english:"Sun Java System Identity Manager Account Disclosure");
  script_summary(english:"Checks if the application is leaking information");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host is running a web application with information\n",
      "disclosure vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Sun Java System Identity Manager running on the remote\n",
      "host has the following account enumeration vulnerabilities :\n\n",
      "- The error message for a failed login attempt is different,\n",
      "  depending on whether or not a valid username was given.\n\n",
      "- Requesting IDMROOT/questionLogin.jsp?accountId=USERNAME results in\n",
      "  different results, depending on whether USERNAME is valid.\n\n",
      "A remote attacker could use these to enumerate valid usernames,\n",
      "which could be used to mount further attacks.\n\n",
      "There are also other issues known to be associated with this version\n",
      "of Identity Manager that Nessus has not tested for. Refer to Sun\n",
      "Security Alert #253267 for more information."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blogs.sun.com/security/entry/sun_alert_253267_sun_java"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-253267-1"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "The vendor has made a patch available. It fixes other unrelated\n",
      "vulnerabilities, but only partially addresses this issue. At this\n",
      "time, there is no known comprehensive solution."
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

  script_dependencies("sun_idm_detect.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


fake_user = string(SCRIPT_NAME, "-", unixtime());

port = get_http_port(default:80, embedded: 0);

# Only does the check if Sun IDM was already detected on the remote host
install = get_kb_item(string("www/", port, "/sun_idm"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{
  dir = matches[2];

  # Tries to get prompted for the security question of a nonexistent user.
  url = string(dir, "/questionLogin.jsp?accountId=", fake_user);
  res = http_send_recv3(
    method:"GET",
    item:url,
    port:port,
    follow_redirect:1
  );

  if (isnull(res)) exit(0);

  # If the server explicitly says the user does not exist,
  # this host is vulnerable
  if ('The specified user was not found.' >< res[2])
  {
    security_warning(port);
    exit(0);
  }

  # If the 'Forgot Password' method didn't leak information, see if
  # logging in as a nonexistent user will
  url = string(dir, "/login.jsp");
  postdata = 'command=login&accountId=' + fake_user;
  res = http_send_recv3(
    method:"POST",
    item:url,
    port:port,
    data:postdata,
    add_headers : make_array(
      "Content-Type", "application/x-www-form-urlencoded"
    )
  );

  if (isnull(res)) exit(0);

  if ('Invalid Account ID' >< res[2]) security_warning(port);
}

