#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15949);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(11889); 
 script_xref(name:"OSVDB", value:"12335");

 script_name(english:"PhpDig < 1.8.5 Unspecified Vulnerability");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is affecetd by an unspecified flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpDig, an open-source search engine
written in PHP. 

The remote version of this software is affected by a vulnerability which
may allow an attacker to temper with the integrity of the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.8.5 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Checks the version of phpMyAdmin");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 r = http_send_recv3(method:"GET", port:port, item:dir + "/search.php");
 if (isnull(r)) exit(0);
 # <title>PhpDig 1.8.4</title>
 if ( "<title>PhpDig" >< r[2])
 {
  if ( egrep(pattern:"<title>PhpDig (0\.|1\.([0-7]\.|8\.[0-4][^0-9]))", string:r[2]) )
	{
	 security_warning(port);
	 exit(0);
	}
 }
}
