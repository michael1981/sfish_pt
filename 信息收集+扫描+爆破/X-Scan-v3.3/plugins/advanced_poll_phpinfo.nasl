#
# This script was written by Renaud Deraison
#


include("compat.inc");

if(description)
{
 script_id(11487);
 script_version ("$Revision: 1.12 $");

 script_cve_id("CVE-2003-1181");
 script_bugtraq_id(7171);
 script_xref(name:"OSVDB", value:"3292");
 
 script_name(english:"Advanced Poll info.php Remote Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Chien Kien Uong's Advanced Poll, a simple
Poll system using PHP. 

By default, this utility includes a file named 'info.php' that makes a
call to 'phpinfo()' and displays a lot of information about the remote
host and how PHP is configured.  An attacker may use this flaw to gain
a more intimate knowledge about the remote host and better prepare its
attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/342493" );
 script_set_attribute(attribute:"solution", value:
"Delete the affected file." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 summary["english"] = "Checks for the presence of info.php";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( !can_host_php(port:port) ) exit(0);


foreach dir (list_uniq(make_list("/poll", cgi_dirs())))
{
 r = http_send_recv3(method:"GET", item:string(dir, "/misc/info.php"), port:port);
 if (isnull(r)) exit(0);
 res = r[2];
 if("<title>phpinfo()</title>" >< res)
 	{
	security_warning(port);
	exit(0);
	}
}
