#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42055);
 script_version ("$Revision: 1.1 $");

 script_name(english: "CGI Generic Format String Vulnerability");
 script_summary(english: "Tortures the arguments of the remote CGIs (format string)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize request strings.  They seem to be vulnerable to a 'format
string' attack.  By leveraging this issue, an attacker may be able to
execute arbitrary code on the remote host subject to the privileges
under which the web server operates. 

Please inspect the results as this script is prone to false positives." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Format_string_attack" );
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application / scripts.  And contact
the vendor for a patch or upgrade.");
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/07");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_timeout(432000);	# Timeout is managed by the script itself
 script_require_keys("Settings/enable_web_app_tests", "Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

if (report_paranoia < 2) exit(1, "This script only runs if report paranoia is set to 'Paranoid'.");

####

i = 0; 
flaws_and_patterns = make_array(
"%08x",		"RE:[0-9a-fA-F]{8}"
);

init_torture_cgi();

port = get_http_port(default:80, embedded: embedded);

report = torture_cgis(port: port, vul: "FS", exclude_cgi: "\.(php[3-5]?|pl)$");

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
  if (COMMAND_LINE) display(report, '\n');
}
