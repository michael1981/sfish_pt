#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17272);
  script_version ("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0658");
  script_bugtraq_id(12721);
  script_xref(name:"OSVDB", value:"14362");

  script_name(english:"TYPO3 cmw_linklist Extension category_uid Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The installation of TYPO3 on the remote host is vulnerable to remote
SQL injection attacks through the parameter 'category_uid' used by the
third-party cmw_linklist extension.  By exploiting this flaw, a remote
attacker may be able to uncover sensitive information or even modify
existing data." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0065.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-03/0075.html" );
 script_set_attribute(attribute:"see_also", value:"http://typo3.org/typo3-20050304-1.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to cmw_linklist extension version 1.5.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Detects SQL injection vulnerability in TYPO3 CMW Linklist extension");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/typo3", "/site", "/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Check if the extension is available.
  #
  # nb: the flaw is in pi1/class.tx_cmwlinklist_pi1.php so check for that.
  w = http_send_recv3(method:"GET", item:string(dir, "/typo3conf/ext/cmw_linklist/pi1/class.tx_cmwlinklist_pi1.php"), port:port);
  if (isnull(w)) exit(1, "the web server did not answer");

  # If it is...
  if (w[0] =~ "^HTTP/.+ 200 OK") {
    # Grab the main page.
    w = http_send_recv3(method:"GET", item:string(dir, "/index.php"), port:port);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # Find the Links page.
    #
    # nb: the actual text could be in the native language or even 
    #     set by the administrator making it hard to get a 
    #     robust pattern. :-(
    pat = '<a href="([^"]+)".+(Links</a>|name="links")';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      links = eregmatch(pattern:pat, string:match);
      if (!isnull(links)) {
        links = links[1];
        if (links !~ "^/") links = "/" + links;
        break;
      }
    }

    # Find a single link in the Links page (which should be local).
    if (!isnull(links) && links !~ "^http") {
      w = http_send_recv3(method:"GET", item:string(dir, links), port:port);
      if (isnull(w)) exit(1, "the web server did not answer");
      res = w[2];

      pat = '<A HREF="([^"]+&action=getviewcategory[^"]*">';
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      foreach match (split(matches)) {
        match = chomp(match);
        link = eregmatch(pattern:pat, string:match);
        if (!isnull(link)) {
          link = link[1];
          break;
        }
      }

      # Try to exploit vulnerability by issuing an impossible request.
      #
      # nb: The fix for the vulnerability evaluates category_uid as an 
      #     integer; thus, it's vulnerable if the result fails to
      #     return any links.
      if (link) {
        exploit = ereg_replace(
          string:link,
          pattern:"&category_uid=([0-9]+)",
          # cause query to fail by tacking " and 1=0 " onto the category_uid.
          replace:"\1%20and%201=0%20"
        );
        w = http_send_recv3(method:"GET", item:exploit, port:port);
	if (isnull(w)) exit(1, "the web server did not answer");
	res = w[2];

        # If there aren't any links, there's a problem.
        if (res !~ "&action=getviewclickedlink&uid=") {
          security_hole(port);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
          exit(0);
        }
      }
    }
  }
}
