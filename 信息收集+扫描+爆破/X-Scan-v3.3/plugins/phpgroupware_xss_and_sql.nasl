#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15983);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2004-1383", "CVE-2004-1384", "CVE-2004-1385");
 script_bugtraq_id(11952);
 script_xref(name:"OSVDB", value:"12390");
 script_xref(name:"OSVDB", value:"12391");
 script_xref(name:"OSVDB", value:"12392");
 script_xref(name:"OSVDB", value:"12393");
 script_xref(name:"OSVDB", value:"12394");
 script_xref(name:"OSVDB", value:"12395");
 script_xref(name:"OSVDB", value:"12396");

 script_name(english:"phpGroupWare <= 0.9.16.003 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, is a multi-user
groupware suite written in PHP. 

The remote version of this software is vulnerable to two issues :

- A cross site scripting issue may allow an attacker to steal the
credentials of third-party users of the remote host ;

- A SQL injection vulnerability may allow an attacker to execute
arbitrary SQL statements against the remote database." );
 script_set_attribute(attribute:"solution", value:
"Update to the newest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks the version of phpGroupWare");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8][^0-9]|9\.([0-9][^0-9]|1([0-5][^0-9]|6\.(00[0-3]|RC[0-9]))))", string:matches[1]))
{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
