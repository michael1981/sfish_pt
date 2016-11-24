#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12093);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2004-1809");
 script_bugtraq_id(9865, 9866);
 script_xref(name:"OSVDB", value:"4257");
 script_xref(name:"OSVDB", value:"4259");
 
 script_name(english:"phpBB < 2.0.7 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote CGI is vulnerable to cross site scripting." );
 script_set_attribute(attribute:"description", value:
"There is a cross site scripting vulnerability in the files 
'ViewTopic.php' and 'ViewForum.php' in the remote installation of phpBB." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.0.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"XSS test");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("phpbb_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if ( get_kb_item("www/"+port+"/generic_xss") ) exit(0);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
dir = matches[2];

r = http_send_recv3(method: "GET", item:dir + "/viewtopic.php?t=10&postdays=99<script>foo</script>", port:port);
if (isnull(r)) exit(0);

r2 = http_send_recv3(method: "GET", item:dir + "/viewforum.php?f=10&postdays=99<script>foo</script>", port:port);
if (isnull(r2)) exit(0);

if("<script>foo</script>" >< r[2] || "<script>foo</script>" >< r2[2])
{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
