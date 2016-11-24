#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20295);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-4148", "CVE-2005-4149");
  script_bugtraq_id(15789);
  script_xref(name:"OSVDB", value:"21552");
  script_xref(name:"OSVDB", value:"49944");

  script_name(english:"ListManager Error Message Information Disclosure");
  script_summary(english:"Checks for error message information disclosure vulnerability in ListManager");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to an information disclosure
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running ListManager, a web-based
commercial mailing list management application from Lyris. 

In response to a request for a nonexistent page, the version of
ListManager on the remote host returns sensitive information such as
the installation path and software version as well as possibly SQL
queries, code blocks, or the entire CGI environment." );
 script_set_attribute(attribute:"see_also", value:"http://metasploit.com/research/vulnerabilities/lyris_listmanager/" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-12/0349.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure it's ListManager, unless we're being paranoid.
banner = get_http_banner(port:port);
if (
  report_paranoia < 2 &&
  banner && 
  (
    # later versions of ListManager
    "ListManagerWeb/" >!< banner &&
    # earlier versions (eg, 8.5)
    "Server: Tcl-Webserver" >!< banner
  )
) exit(0);


# Try to exploit the flaw.
url = string("/read/rss?forum=", SCRIPT_NAME);
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we see a bug report form.
if (egrep(pattern:'<INPUT TYPE="HIDDEN" NAME="(currentdir|env|version)', string:res)) {
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus was able to uncover some information using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    if (report_verbosity > 1)
    {
      info = "";
      foreach var (make_list("currentdir", "env", "version"))
      {
        leadin = string('<INPUT TYPE="HIDDEN" NAME="', var, '" VALUE="');
        if (leadin >< res)
        {
          val = strstr(res, leadin) - leadin;
          val = val - strstr(val, '">');
          info += '  ' + var + ' : ' + val + '\n';
        }
      }
      report = string(
        report,
        "\n",
        "Here is the information extracted :\n",
        "\n",
        info
      );
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
