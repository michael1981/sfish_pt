#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(17194);
  script_version("$Revision: 1.9 $");
  script_cve_id("CVE-2005-0512");
  script_bugtraq_id(12608);
  script_xref(name:"OSVDB", value:"14021");

  script_name(english:"Mambo Open Source Tar.php Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include flaw." );
 script_set_attribute(attribute:"description", value:
"The version of Mambo Open Source on the remote host fails to properly
sanitize input passed through the 'mosConfig_absolute_path' parameter
of the 'Tar.php' script.  Provided PHP's 'register_globals' setting is
enabled, a remote attacker may exploit this vulnerability to cause
code to be executed in the context of the user running the web service
or to read arbitrary files on the target." );
 script_set_attribute(attribute:"see_also", value:"http://forum.mamboserver.com/showthread.php?t=32119" );
 script_set_attribute(attribute:"see_also", value:"http://mamboxchange.com/frs/shownotes.php?group_id=5&release_id=3054" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mambo Open Source 4.5.2.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Detect Tar.php Remote File Include Vulnerability in Mambo Open Source";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  req = http_get(
    item:string(
      dir, "/includes/Archive/Tar.php?",
      "mosConfig_absolute_path=../../CHANGELOG%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if ("Mambo is Free Software" >< res) security_warning(port);
}
