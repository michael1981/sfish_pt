#
# (C) Tenable Network Security, Inc.
#


if ( NASL_LEVEL < 3000 ) exit(0);
include("compat.inc");

if (description)
{
  script_id(36117);
  script_version("$Revision: 1.9 $");

  script_cve_id(
    "CVE-2008-3761",
    "CVE-2008-4916",
    "CVE-2009-0177",
    "CVE-2009-0518",
    "CVE-2009-0908",
    "CVE-2009-0909",
    "CVE-2009-0910",
    "CVE-2009-1146",
    "CVE-2009-1147",
    "CVE-2009-1244",
    "CVE-2009-1805"
  );
  script_bugtraq_id(34373, 34471, 35141);
  script_xref(name:"milw0rm", value:"6262");
  script_xref(name:"milw0rm", value:"7647");
  script_xref(name:"OSVDB", value:"51180");
  script_xref(name:"OSVDB", value:"53409");
  script_xref(name:"OSVDB", value:"53634");
  script_xref(name:"OSVDB", value:"53694");
  script_xref(name:"OSVDB", value:"53695");
  script_xref(name:"OSVDB", value:"53696");
  script_xref(name:"OSVDB", value:"54922");
  script_xref(name:"OSVDB", value:"55942");
  script_xref(name:"OSVDB", value:"55943");
  script_xref(name:"OSVDB", value:"56409");
  script_xref(name:"Secunia", value:"33372");

  script_name(english:"VMware Products Multiple Vulnerabilities (VMSA-2009-0005/VMSA-2009-0007)");
  script_summary(english:"Checks vulnerable versions of multiple VMware products");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
issues." );
 script_set_attribute(attribute:"description", value:
"VMware products installed on the remote host are reportedly affected
by multiple vulnerabilities :

  - A vulnerability in the guest virtual device driver could
    allow an attacker to use the guest operating system to
    crash the host operating system. (CVE-2008-3761)

  - A denial of service vulnerability affects an unspecified
    IOCTL contained in the 'hcmon.sys' driver. An attacker
    can exploit this in order to deny service on a Windows-
    based host. (CVE-2009-1146, CVE-2008-3761)

  - A privilege escalation vulnerability affects the
    'vmci.sys' driver on Windows-based machines. An attacker
    can exploit this in order to gain escalated privileges
    on either the host or the guest. (CVE-2009-1147)

  - The 'VNnc' codec is affected by two heap-based buffer
    overflow vulnerabilities. An attacker can exploit this
    to execute arbitrary code on VMware hosted products by
    tricking a user into opening a malicious file.
    (CVE-2009-0909, CVE-2009-0910)

  - A vulnerability in ACE shared folder may allow attackers
    to enable previously disabled shared ACE folders. This
    only affects VMware ACE. (CVE-2009-0908)

  - A remote denial of service vulnerability affects Windows
    hosts. An attacker can exploit this to crash the
    affected host. (CVE-2009-0177)

  - A vulnerability in the virtual machine display function
    may allow a guest operating system to run code on the
    host. (CVE-2009-1244)

  - A vulnerability in VMware Descheduled Time Accounting
    Service could be exploited to trigger a denial of
    service condition in Windows based virtual machines. It
    should be noted that, this feature is optional, and 
    the vulnerability can be exploited only if the feature 
    is installed, and the affected service is not running in
    the virtual machine. (CVE-2009-1805)" );

 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2009-0005.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2009-0006.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2009-0007.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ws65/doc/releasenotes_ws652.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/player25/doc/releasenotes_player252.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ace25/doc/releasenotes_ace252.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/server2/doc/releasenotes_vmserver201.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to :

  - VMware Workstation 6.5.2 or higher.
  - VMware Server 2.0.1/1.0.9 or higher.
  - VMware Player 2.5.2 or higher.
  - VMware ACE 2.5.2 or higher" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("vmware_workstation_detect.nasl","vmware_server_win_detect.nasl", "vmware_player_detect.nasl", "vmware_ace_detect.nasl");
  script_require_ports("VMware/Server/Version", "VMware/Ace/Version", "VMware/Player/Version", "VMware/Workstation/Version", 139, 445);

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

 if (( int(v[0]) < 6 ) ||
     ( int(v[0]) == 6 && int(v[1]) < 5) ||
     ( int(v[0]) == 6 && int(v[1]) == 5 && int(v[2]) < 2)
   )
     {
       if (report_verbosity > 0)
       {
         report = string(
           "\n",
           "Version ", version," of VMware Workstation is installed on the remote host.",
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
  if ((int(v[0]) == 2 && int(v[1]) == 0 && int(v[2]) < 1) ||
      (
        int(v[0]) < 1 ||
        (
          int(v[0]) == 1 && int(v[1]) == 0 && int(v[2]) < 9
        )
      )
     )    
     {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Version ", version," of VMware Server is installed on the remote host.",
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
  if (( int(v[0]) < 2 ) ||
      ( int(v[0]) == 2 && int(v[1]) < 5) ||
      ( int(v[0]) == 2 && int(v[1]) == 5 && int(v[2]) < 2)
    )
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Version ", version," of VMware Player is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
      }
      else
        security_hole(port);
    }
}

#Check for VMware ACE
version = get_kb_item("VMware/ACE/Version");
if (version)
{
  v = split(version, sep:".", keep:FALSE);
  if (( int(v[0]) < 2) ||
      ( int(v[0]) == 2 && int(v[1]) < 5 ) ||
      ( int(v[0]) == 2 && int(v[1]) == 5 && int(v[2]) < 2 )
    )
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Version ", version," of VMware ACE is installed on the remote host.",
          "\n"
        );
        security_hole(port:port, extra:report);
      }
      else
        security_hole(port);
    }
}
