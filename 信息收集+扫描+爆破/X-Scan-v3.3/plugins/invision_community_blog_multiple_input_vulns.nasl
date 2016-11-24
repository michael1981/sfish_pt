#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18446);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-1945", "CVE-2005-1946");
  script_bugtraq_id(13910);
  script_xref(name:"OSVDB", value:"17210");
  script_xref(name:"OSVDB", value:"17211");

  script_name(english:"Invision Community Blog Multiple Vulnerabilities (SQLi, XSS)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Invision Community Blog, a plugin for
Invision Power Board that lets users have their own blogs. 

The version installed on the remote host fails to properly sanitize
user-supplied data making it prone to multiple SQL injection and
cross-site scripting vulnerabilities.  These flaws may allow an
attacker to gain access to sensitive information such as passwords and
cookie data." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00078-06072005" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Invision Community Blog 1.1.2 Final or greater." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple input validation vulnerabilities in Invision Community Blog";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # To exploit it, we need to find an existing blog.
  r = http_send_recv3(method: "GET", item:string(dir, "/index.php?automodule=blog"), port:port);
  if (isnull(r)) exit(0);

  pat = string(dir, "/index.php?s=.+&amp;automodule=blog&amp;blogid=([0-9]+)&amp;");
  matches = egrep(string: r[2], pattern:pat, icase:TRUE);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      blog = eregmatch(pattern:pat, string:match);
      if (!isnull(blog)) {
        blog = blog[1];

        # Try to exploit one of the SQL injection vulnerabilities.
        r = http_send_recv3(method: "GET", 
          item:string(
            dir, "/index.php?",
            "automodule=blog&",
            "blog=", blog, "&",
            "cmd=editentry&",
            # nb: look for this exploit string later.
            "eid=99'", SCRIPT_NAME
          ),
          port:port
        );
        if (isnull(r)) exit(0);

        if (
          "an error in your SQL syntax" >< r[2] &&
          egrep(
            string:r[2], 
            pattern:string("SELECT \* FROM .*entries WHERE entry_id = 99&amp;#39;", SCRIPT_NAME)
          )
        ) {
          security_warning(port);
	  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
          exit(0);
        }

        # We're not vulnerable, but we're finished checking too.
        break;
      }
    }
  }
}
