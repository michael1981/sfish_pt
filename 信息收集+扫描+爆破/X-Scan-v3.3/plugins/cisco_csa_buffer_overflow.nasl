#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32131);
  script_version("$Revision: 1.4 $");
 
  script_cve_id("CVE-2007-5580");
  script_bugtraq_id(26723);
  script_xref(name:"OSVDB", value:"39521");

  script_name(english:"Cisco Security Agent for Microsoft Windows Crafted SMB Packet Remote Overflow");
  script_summary(english:"Checks Cisco Security Agent version"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Cisco Security Agent installed on the remote host is
affected by a buffer overflow vulnerability.  By sending a specially-
crafted SMB request to the agent, an unauthenticated attacker may be
able to execute arbitrary code with SYSTEM level privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484669" );
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/warp/public/707/cisco-sa-20071205-csa.shtml" );
 script_set_attribute(attribute:"solution", value:
" - Cisco Security Agent version 4.5.1, upgrade to 4.5.1.672
 - Cisco Security Agent version 5.0,   upgrade to 5.0.0.225
 - Cisco Security Agent version 5.1,   upgrade to 5.1.0.106
 - Cisco Security Agent version 5.2,   upgrade to 5.2.0.238" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("cisco_csa_installed.nasl");
  script_require_keys("Cisco/CSA/Version");
  script_require_ports(139, 445);
  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

port = kb_smb_transport();

# Check for Cisco CSA Version

version = get_kb_item("Cisco/CSA/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);

 if (( int(v[0]) < 4 ) ||
     ( int(v[0]) == 4 && int(v[1])  < 5 ) ||
     ( int(v[0]) == 4 && int(v[1]) == 5 && int(v[2]) < 1 ) ||
     ( int(v[0]) == 4 && int(v[1]) == 5 && int(v[2]) == 1 && int(v[3]) < 672 ) ||
     ( int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) == 0 && int(v[3]) < 225 ) ||
     ( int(v[0]) == 5 && int(v[1]) == 1 && int(v[2]) == 0 && int(v[3]) < 106 ) ||
     ( int(v[0]) == 5 && int(v[1]) == 2 && int(v[2]) == 0 && int(v[3]) < 238 ) 
    )
     {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Cisco Security Agent version ",version," is installed on the remote host.\n"
        );
        security_hole(port:port, extra:report);
       }  	
       else
   	 security_hole(port);
     }
}
