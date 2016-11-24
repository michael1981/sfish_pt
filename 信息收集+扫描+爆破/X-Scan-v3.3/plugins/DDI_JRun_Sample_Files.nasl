#
# This script was written by H D Moore
# 
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#
# Changes by Tenable:
# - Updated title (12/8/2008)
# - Changed family (12/8/2008)
# - Added OSVDB refs, updated title (1/22/2009)
# - Lowered Severity (10/4/2009)


include("compat.inc");

if(description)
{
    script_id(10996);
    script_version ("$Revision: 1.21 $");

    script_cve_id("CVE-2000-0539", "CVE-2000-0540");
    script_bugtraq_id(1386);
    script_xref(name:"OSVDB", value:"2713");
    script_xref(name:"OSVDB", value:"51282");
    script_xref(name:"OSVDB", value:"51283");

    script_name(english:"JRun Multiple Sample Files Remote Information Disclosure");
    script_summary(english:"Checks for the presence of JRun sample files");

     script_set_attribute(attribute:"synopsis", value:
"The remote web server suffers from information disclosure flaws." );
     script_set_attribute(attribute:"description", value:
"This host is running the Allaire JRun web server and has sample files
installed.  Several of the sample files that come with JRun contain
serious security flaws.  An attacker can use these scripts to relay
web requests from this machine to another one or view sensitive
configuration information as well as all the session IDs that are
currently in use by the server. 

Sample files should never be left on production servers." );
     script_set_attribute(attribute:"see_also", value:
"http://www.adobe.com/devnet/security/security_zone/asb00-15.html" );
     script_set_attribute(attribute:"solution", value:
"Remove the sample files and any other files that are not required.");
    script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
    script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
    script_end_attributes();

    script_category(ACT_GATHER_INFO);

    script_copyright(english:"This script is Copyright (C) 2001-2009 Digital Defense Inc.");

    script_family(english:"CGI abuses");
    script_dependencie("http_version.nasl");
    script_require_ports("Services/www", 80);
    script_exclude_keys("Settings/disable_cgi_scanning");
    exit(0);
}

include("http_func.inc");
include("global_settings.inc");
include("http_keepalive.inc");

#
# The script code starts here
#


file[0] = "/cfanywhere/index.html";     res[0] = "CFML Sample";
file[1] = "/docs/servlets/index.html";  res[1] = "JRun Servlet Engine";
file[2] = "/jsp/index.html";            res[2] = "JRun Scripting Examples";
file[3] = "/webl/index.html";           res[3] = "What is WebL";

port = get_http_port(default:80);

function check_page(req, pat)
{
    local_var	str, r;
    str = http_get(item:req, port:port);
    r = http_keepalive_send_recv(data:str, port:port);
    if( isnull(r) ) exit(0);
    if(pat >< r)
            {
                security_warning(port:port);
                exit(0);
            }
    return(0);
}

for(i=0;file[i];i=i+1)
{
    req = file[i];
    pat = res[i];
    check_page(req:req, pat:pat);
}
