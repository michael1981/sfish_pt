#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);



include("compat.inc");

if (description)
{
  script_id(21556);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-1249", "CVE-2006-1453", "CVE-2006-1454", "CVE-2006-1458", "CVE-2006-1459", 
                "CVE-2006-1460", "CVE-2006-1461", "CVE-2006-1462", "CVE-2006-1463", "CVE-2006-1464", 
                "CVE-2006-1465", "CVE-2006-2238");
  script_bugtraq_id(17074, 17953);
  script_xref(name:"OSVDB", value:"25508");
  script_xref(name:"OSVDB", value:"25509");
  script_xref(name:"OSVDB", value:"25510");
  script_xref(name:"OSVDB", value:"25511");
  script_xref(name:"OSVDB", value:"25512");
  script_xref(name:"OSVDB", value:"25513");
  script_xref(name:"OSVDB", value:"25514");
  script_xref(name:"OSVDB", value:"25515");
  script_xref(name:"OSVDB", value:"25516");
  script_xref(name:"OSVDB", value:"25517");

  script_name(english:"QuickTime < 7.1 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote version of QuickTime is affected by multiple overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of QuickTime prior to
7.1. 

The remote version of QuickTime is vulnerable to various integer and
buffer overflows involving specially-crafted image and media files. 
An attacker may be able to leverage these issues to execute arbitrary
code on the remote host by sending a malformed file to a victim and
having him open it using QuickTime player." );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2006/May/msg00002.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to QuickTime version 7.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");
  exit(0);
}

#

ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-6]\.|7\.0\.)") security_hole(get_kb_item("SMB/transport"));
