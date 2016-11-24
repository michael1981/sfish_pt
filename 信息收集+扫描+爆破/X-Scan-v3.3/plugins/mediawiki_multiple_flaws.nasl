#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description) {
 script_id(18035);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2004-1405", "CVE-2004-2152", "CVE-2004-2185", "CVE-2004-2186", "CVE-2004-2187");
 script_bugtraq_id(12625, 12444, 12305, 11985, 11897, 11480, 11416, 11302, 10958, 9057);
 script_xref(name:"OSVDB", value:"2819");
 script_xref(name:"OSVDB", value:"10454");
 script_xref(name:"OSVDB", value:"10781");
 script_xref(name:"OSVDB", value:"10782");
 script_xref(name:"OSVDB", value:"10783");
 script_xref(name:"OSVDB", value:"10784");
 script_xref(name:"OSVDB", value:"10785");
 script_xref(name:"OSVDB", value:"10786");
 script_xref(name:"OSVDB", value:"19196");
 script_xref(name:"OSVDB", value:"59519");
 
 script_name(english:"MediaWiki Multiple Remote Vulnerabilities");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
multiple flaws, including arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of MediaWiki before
1.3.11.  Such versions suffer from various vulnerabilities, including
some that may allow an attacker to execute arbitrary PHP code on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=307067" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki 1.3.11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english:"Test for the version of MedaWiki");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_dependencies("mediawiki_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}


include('global_settings.inc');
include("http_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mediawiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.([0-2]\.|3\.([0-9]($|[^0-9])|10))") {
    security_hole(port);
    exit(0);
  }
}
