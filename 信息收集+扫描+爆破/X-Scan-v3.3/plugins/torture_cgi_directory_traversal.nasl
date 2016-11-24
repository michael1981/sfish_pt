#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(39467);
 script_version ("$Revision: 1.5 $");

 script_name(english: "CGI Generic Path Traversal Vulnerability");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be accessed or executed or executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize
request strings and are affected by directory traversal or local files
inclusion vulnerabilities. 

By leveraging this issue, an attacker may be able to read arbitrary 
files on the web server or execute commands." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Directory_traversal" );
 script_set_attribute(attribute:"see_also", value:"http://cwe.mitre.org/data/definitions/22.html");
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the 
vendor for a patch or upgrade." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();

 script_summary(english: "Tortures the arguments of the remote CGIs (traversal)");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/enable_web_app_tests");
 script_timeout(432000);	# Timeout is managed by the script itself
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");


####

i = 0; 
flaws_and_patterns = make_array(
"/etc/passwd",						"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd",			"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd%00",		"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd%00.html",		"RE:root:.*:0:[01]:",
"../../../../../../../../etc/passwd%00index.html",	"RE:root:.*:0:[01]:",
"%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",	"RE:root:.*:0:[01]:",
# (this one is ../../../etc/passwd uuencoded - at least one cgi was vulnerable to this.
"Li4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZAo=",		"RE:root:.*:0:[01]:",
"%60/etc/passwd%60",					"RE:root:.*:0:[01]:",

'..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',	"ST:[windows]",
"../../../../../../../../windows/win.ini",		"ST:[windows]",
'..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini',	"ST:[fonts]",
"../../../../../../../../winnt/win.ini",		"ST:[fonts]",

"/etc",							"ST:resolv.conf",
"../../../../../../../../etc",				"ST:resolv.conf",
"..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc",		"ST:resolv.conf",
"%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc",	"ST:resolv.conf",

"../../../../../../../winnt",		"PI:*system.ini*",
"../../../../../../../windows",		"PI:*system.ini*",
'..\\..\\..\\..\\..\\..\\..\\windows',	"PI:*system.ini*",
'..\\..\\..\\..\\..\\..\\..\\winnt',	"PI:*system.ini*"
);


init_torture_cgi();

port = get_http_port(default:80, embedded: embedded);

report = torture_cgis(port: port, vul: "DT");

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
  if (COMMAND_LINE) display(report, '\n');
}
