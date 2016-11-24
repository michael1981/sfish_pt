#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42056);
 script_version ("$Revision: 1.1 $");

 script_name(english: "CGI Generic Local File Inclusion Vulnerability");
 script_summary(english: "Tortures the arguments of the remote CGIs (local file inclusion)");
 
 script_set_attribute(attribute:"synopsis", value:
"Confidential data may be disclosed on this server." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize 
request strings.  By leveraging this issue, an attacker may be able 
to include a local file and disclose its content." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Remote_File_Inclusion" );
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the vendor 
for a patch or upgrade." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/07");
 script_end_attributes();

 # Not dangerous, but we want to give it a chance to run after the directory traversal and remote injection checks
 script_category(ACT_MIXED_ATTACK);
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

srcRE = 'RE:<\\?php|<%@ +LANGUAGE=.* %>|use +CGI|\\.CreateObject *\\ *\\( *"';

flaws_and_patterns = make_array(
"FILENAME",	srcRE
); 

if (thorough_tests)
  foreach k (make_list("FILENAME%00.html", "FILENAME%00.jpg","FILENAME/."))
     flaws_and_patterns[k] = srcRE;


FP_pattern = "RE:<!-- +<\?php .*\?> *-->";

init_torture_cgi();

port = get_http_port(default:80, embedded: embedded);

report = torture_cgis(port: port, vul: "LI");

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
  if (COMMAND_LINE) display(report, '\n');
}
