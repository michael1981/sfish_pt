#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12094);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2004-2278");
 script_bugtraq_id(9860);
 script_xref(name:"OSVDB", value:"4207");
 
 script_name(english:"vHost < 3.10r1 Unspecified XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of vHost which is older 
than 3.10r1. There is a cross site scripting vulnerability in 
this version which may allow an attacker to steal the cookies 
of the legitimate users of this site." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the vHost 3.10r1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "version test for vHost";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(dir)
{
  local_var	r, time;
  global_var	port;
  time = unixtime();
  r = http_send_recv3(method: "GET", item:dir + "/vhost.php?action=logout&time=" + time, port:port);
  if (isnull(r)) exit(0);

  if ("<!-- vhost" >< r[2] )
   {
    if ( egrep(pattern:"<!-- vhost ([12]\.|3\.([0-9][^0-9]|10[^r]))", string:r[2]) ) {
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
    }
   }
 return(0);
}

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


foreach dir ( cgi_dirs() )
{
 check(dir:dir);
}
