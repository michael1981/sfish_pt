#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(39469);
 script_version ("$Revision: 1.4 $");

 script_name(english: "CGI Generic Remote File Inclusion Vulnerability");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize 
request strings.  By leveraging this issue, an attacker may be able 
to include a remote file from a remote server and execute arbitrary 
commands on the target host." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Remote_File_Inclusion" );
 script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the vendor 
for a patch or upgrade." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_summary(english: "Tortures the arguments of the remote CGIs (remote file inclusion)");
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
s = rand_str();
host = strcat(s, ".example.com");
patt = strcat(s, "\.example\.com");

flaws_and_patterns = make_array(
"http://"+host+"/",	"RE:(inclu[ds]|[fF]ail(ed)? ).*[^/]http://"+patt+"/.*([fF]fail|inclu[sd])"
);
# php_network_getaddresses: getaddrinfo failed: Name or service not known

url = get_kb_item("Settings/HTTP/remote_file_inclusion_URL");
if (strlen(url) > 0)
  if (report_paranoia > 1)
    flaws_and_patterns[url] = "RE:Nessus(CodeExec|FileInclude)Test";
  else
    flaws_and_patterns[url] = "ST:NessusCodeExecTest";

init_torture_cgi();

port = get_http_port(default:80, embedded: embedded);

report = torture_cgis(port: port, vul: "WI");

if (strlen(report) > 0)
{
  security_hole(port:port, extra: report);
  if (COMMAND_LINE) display(report, '\n');
}
