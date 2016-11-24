#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10091);
 script_version ("$Revision: 1.17 $");
 script_xref(name:"OSVDB", value:"57677");
 
 script_name(english:"FTPGate Web Proxy Traversal Arbitrary File Access");
 script_summary(english:"\..\..\file.txt");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a directory traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to read arbitrary files on the remote server by
prepending ../../ or ..\..\ in front of the file name." );
 script_set_attribute(attribute:"solution", value:
"Use another web proxy" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl");
 script_require_ports(8080);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 8080);

foreach d (make_list("windows", "winnt"))
{
  w = http_send_recv3(method:"GET", port: port,
    item:'..\\..\\..\\..\\..\\..\\'+d+'\\win.ini');
 if (isnull(w)) exit(1, "The web server did not answer");
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if("[windows]" >< r || "[fonts]" >< r)
 {
   security_warning(port);
   exit(0);
  }
}
