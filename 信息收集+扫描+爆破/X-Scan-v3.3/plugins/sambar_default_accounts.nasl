#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11493);
 script_version ("$Revision: 1.9 $");

 script_bugtraq_id(2255);
 script_xref(name:"OSVDB", value:"318");

 script_name(english:"Sambar Server Default Accounts");
 
 script_set_attribute(attribute:"synopsis", value:
"Default accounts are active on the remote web server." );
 script_set_attribute(attribute:"description", value:
"The Sambar web server comes with some default accounts.
It is possible to log in as some of them without password.
An attacker may use this flaw to alter the content of this server." );
 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/1998_2/0502.html" );
 script_set_attribute(attribute:"solution", value:
"Set a password for every account or disable it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_summary(english:"Tests for default accounts");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

valid = NULL;
hole = 0;

users = make_list("billy-bob", "admin", "anonymous");

foreach user (users)
{
content = "RCpage=%2Fsysuser%2Fdocmgr%2Fbrowse.stm&onfailure=%2Fsysuser%2Fdocmgr%2Frelogin.htm&path=%2F&RCSsortby=name&RCSbrowse=%2Fsysuser%2Fdocmgr&RCuser=" + user +
"&RCpwd=";


r = http_send_recv3(method: "POST", version: 11, port: port, item: "/session/login", add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"), data: content);

if (isnull(r)) exit(0);

if (ereg(pattern:"^HTTP/[0-9]\.[0-9] 404 ", string: r[0])) exit(0);


if("Sambar Server Document Manager" >< r[2])
 {
 valid += user + '\n';
 if(user == "admin")hole ++;
 }
}

if( valid  )
{
 report = '
It is possible to log in as the following passwordless users in the remote 
Sambar web server :

' +
valid;
 
 security_hole(port:port, extra: report);
}
