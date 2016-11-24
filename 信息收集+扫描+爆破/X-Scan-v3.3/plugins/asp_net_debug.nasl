#
# (C) Tenable Network Security, Inc.
#
#
# Thanks to Adam Poiton for asking us to write this one :)


include("compat.inc");

if(description)
{
 script_id(33270);
 script_version ("$Revision: 1.7 $");
 name["english"] = "ASP.NET DEBUG Method Enabled";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The DEBUG method is enabled on the remote host." );
 script_set_attribute(attribute:"description", value:
"It is possible to send debug statements to the remote ASP scripts.  An
attacker might use this to alter the runtime of the remote scripts" );
 script_set_attribute(attribute:"solution", value:
"Make sure that DEBUG statements are disabled or only usable by
authenticated users." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Tests for ASP.NET Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

files = get_kb_list("www/" + port + "/content/extensions/aspx");
if ( isnull(files) ) exit(0);
else files = make_list(files);

sig = get_http_banner(port:port);
r = http_send_recv3(port: port, item: files[0], method: "DEBUG", version: 11, 
  add_headers: make_array("Command", "stop-debug") );

if (r[0] =~ "^HTTP/1\.1 200 "  &&  'Content-Length: 2\r\n' >< r[1] &&
    r[2] == "OK")
	security_warning(port:port, extra:'\nThe request\n' + egrep(string: http_last_sent_request(), pattern:"^DEBUG /")  + '\nProduces the following output :\n' + r[0]+r[1]+'\r\n'+r[2]);
