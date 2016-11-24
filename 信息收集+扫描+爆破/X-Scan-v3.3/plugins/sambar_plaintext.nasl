#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11585);
 script_version ("$Revision: 1.7 $");

 script_name(english:"Sambar Server Cleartext Password Transmission");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows credential to be transmitted in clear
text." );
 script_set_attribute(attribute:"description", value:
"The remote Sambar server allows user to log in without using SSL.

An attacker with a sniffer on the way between a user's host and
this server may use this flaw to capture the password of the 
users of this server.

With the password, he could then be able to access the webmail
accounts and modify the webpages on behalf of its victim." );
 script_set_attribute(attribute:"solution", value:
"Use Sambar on top of SSL." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Makes sure that Sambar runs on top of SSL");
 
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

user = "whatever";
content = "RCpage=%2Fsysuser%2Fdocmgr%2Fbrowse.stm&onfailure=%2Fsysuser%2Fdocmgr%2Frelogin.htm&path=%2F&RCSsortby=name&RCSbrowse=%2Fsysuser%2Fdocmgr&RCuser=" + user +
"&RCpwd=";


r = http_send_recv3(method: "POST", item: "/session/login", port: port, version: 11, add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"), data: content);


if (isnull(r)) exit(0);

if (ereg(pattern:"^HTTP/[0-9]\.[0-9] 404 ", string: r[0])) exit(0);
if (ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string: r[0]) &&
   "SAMBAR" >< r[0]+r[1]+r[2])
{
    transport = get_port_transport(port);
    if(transport == ENCAPS_IP) security_note(port);
}
