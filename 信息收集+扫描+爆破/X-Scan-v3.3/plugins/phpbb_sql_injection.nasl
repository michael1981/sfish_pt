#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(11767);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2003-0486");
 script_bugtraq_id(7979);
 script_xref(name:"OSVDB", value:"2186");
 
 script_name(english:"phpBB viewtopic.php topic_id Variable SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to SQL injection." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpBB.

There is a flaw in the remote software which may allow anyone to inject
arbitrary SQL commands, which may in turn be used to gain administrative
access on the remote host or to obtain the MD5 hash of the password of 
any user." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 script_summary(english: "SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
dir     = matches[2];

r = http_send_recv3(method: "GET", item:dir + "/viewtopic.php?sid=1&topic_id='", port:port);
if (isnull(r)) exit(0);
buf = strcat(r[0], r[1], '\r\n', r[2]);

if("SELECT t.topic_id, t.topic_title, t.topic_status" >< buf)
{
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

