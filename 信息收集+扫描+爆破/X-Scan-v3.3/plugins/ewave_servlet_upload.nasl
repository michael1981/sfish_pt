#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/9/2009)


include("compat.inc");

if(description)
{
 script_id(10570);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-1024");
 script_bugtraq_id(1876);
 script_xref(name:"OSVDB", value:"469");

 script_name(english:"Unify eWave ServletExec 3.0C UploadServlet Unprivileged File Upload");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be overwritten on the remote host." );
 script_set_attribute(attribute:"description", value:
"ServletExec has a servlet called 'UploadServlet' in its server
side classes. UploadServlet, when invokable, allows an
attacker to upload any file to any directory on the server. The
uploaded file may have code that can later be executed on the
server, leading to remote command execution." );
 script_set_attribute(attribute:"solution", value: "Remove it." );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();

 
 script_summary(english:"Unify eWave ServletExec 3.0C file upload");

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"/servlet/nessus." + string(rand(),rand(), rand()), port:port);
if ( res ) exit(0);

res = is_cgi_installed_ka(item:"/servlet/com.unify.servletexec.UploadServlet", port:port);
if(res)
{
 security_hole(port);
}

