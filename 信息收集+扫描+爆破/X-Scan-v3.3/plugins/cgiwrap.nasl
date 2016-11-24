#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10041);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-1999-1530", "CVE-2000-0431");
 script_bugtraq_id(777, 1238);
 script_xref(name:"OSVDB", value:"35");
 script_xref(name:"OSVDB", value:"1346");

 script_name(english:"Cobalt RaQ2 cgiwrap Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host has 'cgiwrap' is installed. If you are running an 
unpatched Cobalt RaQ, the version of cgiwrap distributed with that
system has a known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

This flaw exists only on the Cobalt modified cgiwrap. Standard builds
of cgiwrap are not affected." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/1558.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/1533.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-05/0259.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-05/0305.html" );
 script_set_attribute(attribute:"solution", value:
"Cobalt Networks has released a patch that addresses the vulnerability." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();


 summary["english"] = "Checks for the presence of /cgi-bin/cgiwrap";
   
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2009 Mathieu Perrin");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
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
res = is_cgi_installed_ka(item:"cgiwrap", port:port);
if(res)security_hole(port);

   
