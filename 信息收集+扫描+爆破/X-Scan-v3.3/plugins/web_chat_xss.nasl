#
# (C) Tenable Network Security, Inc.
#
# Ref:
#  Date: Tue, 25 Mar 2003 12:11:24 +0300
#  From: "Over_G" <overg@mail.ru>
#  To: vuln@security.nnov.ru, bugtraq@securityfocus.com
#  Subject: CSS in PHP WEB CHAT
#
#
# NOTE: It was impossible to check for this flaw, as the author
# apparently do not distribute this product any more (which makes me
# wonder about the impact of this 'flaw')

include( 'compat.inc' );

if(description)
{
  script_id(11470);
  script_bugtraq_id(7190);
  script_version ("$Revision: 1.14 $");

  script_name(english:"WebChat XSS");
  script_summary(english:"XSS in WebChat");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI is vulnerable to an injection attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is vulnerable to a cross site scripting attack through
its web chat module :

- An attacker may create a new user with a bogus email address containing
  javascript code
- Then the profile of the newly created user or the 'lost password' page
  for this user will display the unprocessed java script to the user

An attacker may use this flaw to steal the cookies of your regular users."
  );

  script_set_attribute(
    attribute:'solution',
    value: "None at this time, contact the vendor at http://www.webscriptworld.com."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securityfocus.com/archive/1/316173'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  # Not "destructive" per se, but at least intrusive
  script_category(ACT_DESTRUCTIVE_ATTACK);

  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english: "CGI abuses : XSS");
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);


gdir = make_list(cgi_dirs());

dirs = make_list("", "/chat", "/chat_dir");
foreach d (gdir)
{
  dirs = make_list(dirs, string(d, "/chat"), string(d, "/chat_dir"), d);
}


foreach dir (dirs)
{
 rnd = rand();
 url1 = string(dir, "/register.php?register=yes&username=nessus", rnd, "&email=<script>x=10;</script>&email1=<script>x=10;</script>");

 r = http_send_recv3(method: "GET", item:url1, port:port);
 if (isnull(r)) exit(0);

 if (r[0] =~ "^HTTP/1\.[01] +200 ")
 {
  url2 = string(dir,"/login.php?option=lostpasswd&username=nessus", rnd);
  r = http_send_recv3(method: "GET", item:url2, port:port);
  if (isnull(r)) exit(0);
  if("<script>x=10;</script>" >< r[2])
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
 }
}
