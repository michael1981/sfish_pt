#
# Msadcs.dll locate.
#
# This plugin was written in NASL by RWT roelof@sensepost.com
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/23/09)


include("compat.inc");

if(description)
{
 script_id(10357);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-1999-1011");
 script_bugtraq_id(529);
 script_xref(name:"OSVDB", value:"272");
 script_xref(name:"IAVA", value:"1999-a-0010");
 script_xref(name:"IAVA", value:"1999-t-0003");

 script_name(english:"Microsoft IIS MDAC RDS (msadcs.dll) Arbitrary Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote command execution 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The web server is probably susceptible to a common IIS vulnerability 
discovered by 'Rain Forest Puppy'. This vulnerability enables an 
attacker to execute arbitrary commands on the server with 
Administrator Privileges. 

*** Nessus solely relied on the presence of the file /msadc/msadcs.dll
*** so this might be a false positive" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;[LN];184375" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS98-004.mspx" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS99-025.mspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MDAC version 2.1 SP2 or higher, as it has been reported to 
fix this vulnerability. It is also possible to correct the flaw by 
implementing the following workaround: Delete the /msadc virtual 
directory in IIS." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Determines the presence of msadcs.dll");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Roelof Temmingh <roelof@sensepost.com>");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if ( ! get_port_state(port) )  exit(0);
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

cgi = "/msadc/msadcs.dll";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);
