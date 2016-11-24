#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(34156);
  script_version("$Revision: 1.8 $");

  script_cve_id(
    "CVE-2007-5438",
    "CVE-2008-3691",
    "CVE-2008-3692",
    "CVE-2008-3693",
    "CVE-2008-3694",
    "CVE-2008-3695",
    "CVE-2008-3696",
    "CVE-2008-3697",
    "CVE-2008-3698",
    "CVE-2008-3892",
    "CVE-2008-4279"
  );
  script_bugtraq_id(26025, 30934, 30935, 30936, 31569);
  script_xref(name:"OSVDB", value:"43488");
  script_xref(name:"OSVDB", value:"48246");
  script_xref(name:"OSVDB", value:"48247");
  script_xref(name:"OSVDB", value:"48248");
  script_xref(name:"OSVDB", value:"48249");
  script_xref(name:"OSVDB", value:"48251");
  script_xref(name:"OSVDB", value:"48252");
  script_xref(name:"OSVDB", value:"48253");
  script_xref(name:"OSVDB", value:"48435");
  script_xref(name:"OSVDB", value:"49090");
  script_xref(name:"Secunia", value:"31310");
  script_xref(name:"Secunia", value:"31707");
  script_xref(name:"Secunia", value:"31708");
  script_xref(name:"Secunia", value:"31709");

  script_name(english:"VMware Products Multiple Vulnerabilities (VMSA-2008-0014)");
  script_summary(english:"Checks versions of multiple VMware products"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"A VMware product installed on the remote host is affected by multiple
vulnerabilities :

  - ActiveX controls provided by VMware for IE could be 
    exploited to cause a denial-of-service condition or
    execute arbitrary code on the remote system. 
    (CVE-2007-5438, CVE-2008-3691-CVE-2008-3696,
    CVE-2008-3892)

  - Internet Server Application Programming Interface 
    (ISAPI) extensions provided by VMware are affected
    by a remote denial of service vulnerability.
    (CVE-2008-3697)

  - Certain VMware products running as host systems are 
    affected by a local privilege escalation vulnerability. 
    Successful exploitation of this issue would allow 
    users to execute arbitrary code on the system.
    (CVE-2008-3698)
  
  - A flaw in VMWare's CPU hardware emulation could result
    in privilege escalation on guest systems running on 
    64-bit operating systems. (CVE-2008-4279)" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/495869/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-10/0051.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2008-0014.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2008-0016.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to :

 - VMware Workstation 6.0.5/5.5.8 or higher.
 - VMware Player 2.0.5/1.0.8 or higher.
 - VMware Server 1.0.7 or higher.
 - VMware ACE 2.0.5/1.0.7 or higher." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("vmware_workstation_detect.nasl","vmware_server_win_detect.nasl",
		      "vmware_player_detect.nasl","vmware_ace_detect.nasl");
  script_require_ports("VMware/Server/Version", "VMware/Ace/Version",
  "VMware/Player/Version", "VMware/Workstation/Version", 139, 445);
  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

port = kb_smb_transport();

# Check for VMware Workstation

version = get_kb_item("VMware/Workstation/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

 if (( v[0]  < 5 ) ||
     ( v[0] == 5 && v[1]  < 5 ) ||
     ( v[0] == 5 && v[1] == 5 && v[2] < 8 ) ||
     ( v[0] == 6 && v[1] == 0 && v[2] < 5 )
    )
     {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Workstation is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
       }  	
       else
   	 security_hole(port);
     }
}

# Check for VMware Server

version = get_kb_item("VMware/Server/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

 if ( ( v[0]  < 1 ) ||
      ( v[0] == 1  && v[1] == 0 && v[2] < 7 )
    )
   {
     if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Server is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
       }	
       else
    	security_hole(port);
    }
}

# Check for VMware Player

version = get_kb_item("VMware/Player/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);
 for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

 if ( ( v[0]  < 1 ) ||
      ( v[0] == 1  && v[1] == 0 && v[2] < 8 ) ||
      ( v[0] == 2  && v[1] == 0 && v[2] < 5 )
    )
   {
     if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Version ",version," of VMware Player is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
       }
       else
        security_hole(port);
    }
}

# Check for VMware ACE.

version = get_kb_item("VMware/ACE/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);

 for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

 if (( v[0] == 1  && v[1] == 0 && v[2] < 7 ) ||
     ( v[0] == 2  && v[1] == 0 && v[2] < 5 )
    )	
  {
    if (report_verbosity > 0)
    {
      report = string(
         "\n",
         "Version ",version," of VMware ACE is installed on the remote host.",
         "\n"
      );
      security_hole(port:port, extra:report);
    }
    else
       security_hole(port);
  }
}
