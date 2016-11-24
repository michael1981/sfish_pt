# Written by DokFLeed <dokfleed at dokfleed.net>
# Looking for smency.nsf Trend/Lotus
#

# Changes by Tenable:
# - Revised plugin title (4/3/2009)


include("compat.inc");

if(description)
{
   script_id(14312);
   script_version ("$Revision: 1.9 $");

   script_cve_id("CVE-2004-1003");
   script_bugtraq_id(11612);
   script_xref(name:"OSVDB", value:"11510");

   script_name(english:"Trend Micro Scanmail for Domino nsf File Information Disclosure"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote antivirus is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"This script attempts to read sensitive files used by Trend ScanMail,
an anti-virus protection program for Domino (formerly Lotus Notes).
An attacker, exploiting this flaw, may gain access to confidential
data or disable the anti-virus protection." );
 script_set_attribute(attribute:"solution", value:
"Password protect those files");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P" );
 script_end_attributes();

   script_summary(english:"Checks for the presence ScanMail files"); 
   script_category(ACT_GATHER_INFO); 
   script_family(english:"CGI abuses"); 
   script_copyright(english:"This script is Copyright (C) 2004-2009 by DokFLeed"); 
   script_dependencie("find_service1.nasl", "http_version.nasl");
   script_require_ports("Services/www", 80);
   exit(0); 
}

# Start of Code  
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);


files = make_array("/smency.nsf"   , "Encyclopedia",
                   "/smconf.nsf"   , "Configuration",
                   "/smhelp.nsf"   , "Help",
                   "/smftypes.nsf" , "File Types",
                   "/smmsg.nsf"    , "Messages",
                   "/smquar.nsf"   , "Quarantine",
                   "/smtime.nsf"   , "Scheduler",
                   "/smsmvlog.nsf" , "Log",
                   "/smadmr5.nsf"  , "Admin Add-in");
report = "";
foreach path (keys(files))
{
  req = http_get(item:path, port:port);
  r = http_keepalive_send_recv(port:port, data:req);

  if (r == NULL) exit(0);

  if ("Trend ScanMail" >< r)
  {
    if (!report)
    {
      report =
"The following files were found:
";
    }
    report += string("\n    ", path, " - ", files[path]);
  }
}
if (report) security_warning(port:port, extra:report);
