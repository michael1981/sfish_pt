#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20833);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-3411");
  script_bugtraq_id(15241);
  script_xref(name:"OSVDB", value:"20421");

  script_name(english:"Snitz Forums 2000 post.asp type Parameter XSS");
  script_summary(english:"Checks for type parameter cross-site scripting vulnerability in Snitz Forums 2000");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is prone to a cross-
site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Snitz Forums 2000, a web-based electronic
forum written in ASP. 

The version of Snitz Forums 2000 installed on the remote host fails to
sanitize the 'type' parameter before using it in the 'post.asp' script
to generate dynamic content.  By leveraging this flaw, an attacker may
be able to execute arbitrary HTML and script code in a user's browser
within the security context of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://forum.snitz.com/forum/topic.asp?TOPIC_ID=60011" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Snitz Forums 2000 version 3.4.06 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_asp(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "')</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/forum", "/snitz", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Get the initial page for a list of forums.
  res = http_get_cache(item:string(dir, "/default.asp"), port:port);
  if (isnull(res)) exit(0);

  # If it looks like Snitz Forums 2000...
  if (
    'title>Snitz Forums' >< res ||
    'Snitz Communications<' >< res ||
    'title="Powered By: Snitz Forums' >< res
  )
  {
    # Exploiting the flaw requires an existent forum.
    forum = NULL;

    pat = '<a href="forum.asp?FORUM_ID=([0-9]+)">';
    matches = egrep(pattern:pat, string:res);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE)) {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item)) {
          forum = item[1];
          break;
        }
      }
    }

    # Try to exploit the flaw.
    if (isnull(forum)) {
      debug_print("couldn't find a forum to use!", level:1);
    }
    else {
      req = http_get(
        item:string(
          dir, "/post.asp?",
          "method=Topic&",
          "FORUM_ID=", forum, "&",
          'type=">', exss
        ), 
        port:port
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (isnull(res)) exit(0);

      # If we see our XSS, there's a problem.
      if (xss >< res) {
        security_warning(port);
        set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
  }
}

