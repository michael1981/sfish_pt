#
# (C) Tenable Network Security
#


include("compat.inc");

if(description) {
  script_id(17202);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0477");
  script_bugtraq_id(12607);
  script_xref(name:"OSVDB", value:"14004");
  script_xref(name:"OSVDB", value:"14005");

  script_name(english:"Invision Power Board COLOR SML Tag XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"According to the version number in its banner, the installation of
Invision Power Board on the remote host reportedly does not
sufficiently sanitize the 'COLOR' SML tag.  A remote attacker may
exploit this vulnerability by adding a specially-crafted 'COLOR' tag
with arbitrary JavaScript to any signature or post on an Invision
board.  That JavaScript will later be executed in the context of users
browsing that forum, which may enable an attacker to steal cookies or
misrepresent site content. 

In addition, it has been reported that an attacker can inject
arbitrary script into a signature file. However, Nessus has not tested
for this issue." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-02/0257.html" );
 script_set_attribute(attribute:"see_also", value:"http://forums.invisionpower.com/index.php?showtopic=160633" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N" );
script_end_attributes();

 
  summary["english"] = "Detect Invision Power Board COLOR SML Tag Script Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# nb: don't run unless we're being paranoid since the solution is a patch.
if (report_paranoia < 2) exit(0);


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(1\.([12]\.|3\.[01])|2\.0\.[0-3])")
  {
   security_note(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
