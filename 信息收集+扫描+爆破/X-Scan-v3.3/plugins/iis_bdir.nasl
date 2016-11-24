#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
  script_id(10577);
  script_version ("$Revision: 1.22 $");

  script_bugtraq_id(2280);
  script_xref(name:"OSVDB", value:"475");

  script_name(english:"Microsoft IIS bdir.htr Arbitrary Directory Listing");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The file bdir.htr is a default IIS files which can give a malicious
user a lot of unnecessary information about your file system.
Specifically, the 'bdir.htr' script allows the user to browser and
create files on hard drive.  As this includes critical system files,
it is highly possible that the attacker will be able to use this
script to escalate privileges and gain 'Administrator' access." );
 script_set_attribute(attribute:"solution", value:
"If you do not need these files, then delete them, otherwise use 
suitable access control lists to ensure that the files are not 
world-readable." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

  script_summary(english:"Check for existence of bdir.htr");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"Copyright 2002-2009 John Lampe <j_lampe@bellsouth.net>");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);   
  exit(0);
}



#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

    
port = get_http_port(default:80);

sig = get_http_banner(port:port);
if ( sig && "Server: Microsoft/IIS" >!< sig ) exit(0);
if(get_port_state(port)) 
{
    if(is_cgi_installed_ka(item:"/scripts/iisadmin/bdir.htr", port:port))
    {
        security_warning(port);
        exit(0);
    }
}

