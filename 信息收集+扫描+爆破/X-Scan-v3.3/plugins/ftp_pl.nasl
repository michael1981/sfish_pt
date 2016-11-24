#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10467);
 script_version ("$Revision: 1.26 $");
 script_bugtraq_id(1471);
 script_cve_id("CVE-2000-0674");
 script_xref(name:"OSVDB", value:"366");

 script_name(english:"Virtual Visions FTP ftp.pl dir Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of /cgi-bin/ftp/ftp.pl");
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote ftp server contains a CGI script that provides and HTML
interface. This CGI script contains a vulnerability that an attacker
can use to get the listing of the content of arbitrary directories." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/no404") ) exit(0);


foreach dir (cgi_dirs())
{
 req = string(dir, "/ftp/ftp.pl?dir=../../../../../../etc");
 w = http_send_recv3(method:"GET", item:req, port:port);
 if (isnull(w)) exit(1, "The web server did not answer");
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if("Samba Web Administration Tool" >!< r &&
    "passwd" >< r && r !~ "^HTTP/1\.[01] +4[0-9][0-9] ")
 {
   debug_print("---- ftp.pl on ", get_host_ip(), ":", port, " ----\n", req, "\n--------\n", r, "\n------------\n");
   security_warning(port, extra: 
strcat('Clicking on this URL may show the flaw :\n\n', build_url(port: port, qs: req), '\n'));
   exit(0);
 }
}
