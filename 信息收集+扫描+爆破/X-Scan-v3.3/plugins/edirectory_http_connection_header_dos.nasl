#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31863);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-0927");
  script_bugtraq_id(28757);
  script_xref(name:"OSVDB", value:"44035");

  script_name(english:"Novell eDirectory Host Environment Service (dhost.exe) HTTP Connection Header DoS");
  script_summary(english:"Checks version from an ldap search");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote directory service is affected by a denial-of-service issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running eDirectory, a directory service software
from Novell. 

The installed version of eDirectory is affected by a denial-of-service
issue. By sending an HTTP request with a specially-crafted
'Connection' header to the server, an unauthenticated attacker may be
able to trigger a denial-of-service condition causing dhost.exe to
consume 100% of the CPU and crash the system." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ea8e18c" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to eDirectory 8.8.2/8.7.3 SP10 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "ldap_search.nasl", "os_fingerprint.nasl");
  script_require_keys("Services/ldap");
  script_require_ports(8008,8028,8010,8030);

  exit(0);
}


os = get_kb_item("Host/OS");
if (!os || "Windows" >!< os) exit(0);

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port =  get_http_port(default:8008); # Clear text http port on eDirectory 8.7.3

ldap_port = NULL;
ldap_port = get_kb_item("Services/ldap");
if(isnull(ldap_port)) exit(0);

edir_ldap = get_kb_item(string("LDAP/",ldap_port,"/vendorVersion"));
edir_product = strstr(edir_ldap,"Novell eDirectory");
edir_product = edir_product - strstr(edir_product , "(");

if ( isnull(edir_ldap) || "Novell eDirectory" >!< edir_ldap ) exit(0);

edir_ldap_ver = NULL;

if ("Novell eDirectory 8.7.3" >< edir_ldap)
 {
  edir_ldap_ver = eregmatch(pattern:"^LDAP Agent for Novell eDirectory ([0-9])\.([0-9])\.([0-9])\.*([0-9]*) *\([0-9]+\.[0-9]+\)$", string:edir_ldap);  
  # KB entries
  # LDAP Agent for Novell eDirectory 8.7.3.10 (10555.95) # patched
  # LDAP Agent for Novell eDirectory 8.7.3 (10552.72)    # unpatched

  if ((isnull(edir_ldap_ver[4]) || int(edir_ldap_ver[4]) < 10))
   {
     if(report_verbosity)
      {
        report = string(
          "\n",
	  " ",edir_product," is installed on the remote host.\n"
        );
        security_hole(port:port, extra:report);
      }	
     else	
     security_hole(port); 
   }  
 }

else if ("Novell eDirectory 8.8" >< edir_ldap)
{
 # KB entries
 # LDAP Agent for Novell eDirectory 8.8 (20114.35) # unpatched 
 # LDAP Agent for Novell eDirectory 8.8 SP1 (20114.57) unpatched
 # LDAP Agent for Novell eDirectory 8.8 SP2 (20216.46) # patched
 
     if  ("Novell eDirectory 8.8 SP2" >< edir_ldap) exit(0);
 else if ( ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *SP1 *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap)	||
	   ereg(pattern:"^LDAP Agent for Novell eDirectory 8.8 *\(([0-9]+)\.([0-9]+)\)$",string:edir_ldap)
         )
          { 
            if(report_verbosity)
            {
              report = string(
              "\n",
              " ",edir_product," is installed on the remote host.\n"
              );
              security_hole(port:port, extra:report);
            }
            else
  	    security_hole(port); 
  	    exit (0);
    	} 
}
