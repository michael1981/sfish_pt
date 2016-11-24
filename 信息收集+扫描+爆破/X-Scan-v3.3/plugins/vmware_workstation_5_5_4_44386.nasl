#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25119);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-1069", "CVE-2007-1337", "CVE-2007-1744", "CVE-2007-1876", "CVE-2007-1877");
  script_bugtraq_id(23721, 23732);
  script_xref(name:"OSVDB", value:"35505");
  script_xref(name:"OSVDB", value:"35506");
  script_xref(name:"OSVDB", value:"35507");
  script_xref(name:"OSVDB", value:"35508");
  script_xref(name:"OSVDB", value:"35509");

  script_name(english:"VMware Workstation < 5.5.4 Build 44386 Multiple Vulnerabilities");
  script_summary(english:"Checks version of VMware Workstation"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is
earlier than 5.5.4, Build 44386.  Such versions are reportedly
affected by several issues, including a directory traversal issue in
the application's Shared Folders feature that may allow read or write
access from a guest to a host system, subject to the privileges of the
user running VMware Workstation." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=521" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-04/0487.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/ws55/doc/releasenotes_ws55.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation 5.5.4, Build 44386 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
 
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("VMware/Workstation/Version");
  script_require_ports(139, 445);

  exit(0);
}

version = get_kb_item("VMware/Workstation/Version");
if (!version)
  exit (0);

v = split(version, sep:".", keep:FALSE);

 if ( ( int(v[0]) < 5 ) ||
     ( int(v[0]) == 5 && int(v[1]) < 5 ) ||
     ( int(v[0]) == 5 && int(v[1]) == 5 && int(v[2]) < 4 ) ||
     ( int(v[0]) == 5 && int(v[1]) == 5 && int(v[2]) == 4 && int(v[3]) < 44386 ) )
     {
   	security_hole(get_kb_item("SMB/transport"));
	exit(0);
     }

