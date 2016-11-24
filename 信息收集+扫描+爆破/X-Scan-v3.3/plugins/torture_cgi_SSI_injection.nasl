#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42054);
 script_version ("$Revision: 1.1 $");

 script_name(english:"CGI Generic SSI Injection Vulnerability");
 script_summary(english: "Tortures the arguments of the remote CGIs (SSI injection)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize request strings.  They seem to be vulnerable to an 'SSI
injection' attack.  By leveraging this issue, an attacker may be able
to execute arbitrary commands on the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Server_Side_Includes" );
 script_set_attribute(attribute:"see_also", value:"http://www.owasp.org/index.php/Server-Side_Includes_(SSI)_Injection");
 script_set_attribute(attribute:"see_also", value:"http://cwe.mitre.org/data/definitions/97.html");
 script_set_attribute(attribute:"solution", value:
"Disable Server Side Includes if you do not use them.  Otherwise,
restrict access to any vulnerable scripts and contact the vendor for a
patch or upgrade.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/07");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("webmirror.nasl", "web_app_test_settings.nasl");
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

nosuchfile = strcat("nessus", rand(), ".html");
i = 0; 
flaws_and_patterns = make_array(
# Error messages from thttpd and Apache2
'<!--#include file="'+nosuchfile+'"-->',
	"RE:(The filename requested in a include file directive)|(\[an error occurred while processing this directive\])",
'<!--#exec cmd="cat /etc/passwd"-->', "RE:root:.*:0:[01]:",
'<!--#exec cmd="dir"-->',	"ST:<DIR>"
);

init_torture_cgi();

port = get_http_port(default:80, embedded: embedded);

report = torture_cgis(port: port, vul: "II", exclude_cgi: "\.(php[3-5]?|pl|aspx?)$");

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
  if (COMMAND_LINE) display(report, '\n');
}
