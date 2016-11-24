#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21621);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-2591");
  script_xref(name:"OSVDB", value:"25740");

  script_name(english:"e107 email.php Arbitrary Mail Relay");
  script_summary(english:"Tries to send arbitrary email with e107");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that can be used to send
arbitrary e-mail messages." );
 script_set_attribute(attribute:"description", value:
"The version of e107 installed on the remote host contains a script,
'email.php', that allows an unauthenticated user to send e-mail
messages to arbitrary users and to control to a large degree the
content of those messages.  This issue can be exploited to send spam
or other types of abuse through the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://e107.org/e107_plugins/forum/forum_viewtopic.php?66179" );
 script_set_attribute(attribute:"see_also", value:"http://e107.org/comment.php?comment.news.788" );
 script_set_attribute(attribute:"solution", value:
"Either remove the affected script or upgrade to e107 version 0.7.5 or
later, which uses a 'captcha' system to minimize automated
exploitation of this issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  url = string(dir, "/email.php?", SCRIPT_NAME);

  # Make sure the affected script exists.
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("name='emailsubmit'" >< res)
  {
    # Try to send a message.
    note = string("Test message sent by Nessus / ", SCRIPT_NAME, ".");
    postdata = string(
      "comment=", urlencode(str:note), "&",
      "author_name=nessus&",
      "email_send=nobody@123.zzzz&",
      "emailsubmit=Send+Email"
    );
    r = http_send_recv3(method:"POST ", item:url, port: port,
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if the message was sent.
    if (">Email sent<" >< res)
      security_warning(port);
  }
}
