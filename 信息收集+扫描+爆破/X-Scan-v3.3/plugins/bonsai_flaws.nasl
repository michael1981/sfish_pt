#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11440);
 script_cve_id("CVE-2003-0152", "CVE-2003-0153", "CVE-2003-0154", "CVE-2003-0155");
 script_bugtraq_id(5516, 5517);
 script_xref(name:"OSVDB", value:"5457");
 script_xref(name:"OSVDB", value:"5458");
 script_xref(name:"OSVDB", value:"5459");
 script_xref(name:"OSVDB", value:"5460");
 script_xref(name:"OSVDB", value:"5461");
 script_xref(name:"OSVDB", value:"5462");
 script_xref(name:"OSVDB", value:"5463");
 script_xref(name:"OSVDB", value:"5634");
 script_version ("$Revision: 1.18 $");
		
 script_name(english:"Mozilla Bonsai Mutiple Flaws (Auth Bypass, XSS, Cmd Exec, PD)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a CGI which is vulnerable to multiple flaws
allowing code execution and cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host has the CGI suite 'Bonsai' installed. 

This suite is used to browse a CVS repository with a web browser. 

The remote version of this software is to be vulnerable to various
flaws ranging from path disclosure and cross site scripting to remote
command execution. 

An attacker may exploit these flaws to temper with the integrity of
the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Bonsai" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 script_summary(english:"Determine if bonsai is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dirs = make_list(cgi_dirs());
foreach d (dirs)
{
 url = string(d, "/cvslog.cgi?file=<SCRIPT>window.alert</SCRIPT>");
 r = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "Rcs file" >< buf &&
     "<SCRIPT>window.alert</SCRIPT>" >< buf)
   {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
