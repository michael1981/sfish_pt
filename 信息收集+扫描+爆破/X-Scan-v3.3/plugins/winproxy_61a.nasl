#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20393);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-3187", "CVE-2005-3654", "CVE-2005-4085");
  script_bugtraq_id(16147, 16148, 16149);
  script_xref(name:"OSVDB", value:"22237");
  script_xref(name:"OSVDB", value:"22238");
  script_xref(name:"OSVDB", value:"22239");

  script_name(english:"WinProxy < 6.1a Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks for multiple vulnerabilities in WinProxy < 6.1a");

 script_set_attribute(attribute:"synopsis", value:
"The remote proxy is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WinProxy, a proxy server for Windows. 

According to the Windows registry, the installed version of WinProxy
suffers from denial of service and buffer overflow vulnerabilities in
its telnet and web proxy servers.  An attacker may be able to exploit
these issues to crash the proxy or even execute arbitrary code on the
affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?id=363" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?id=364" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?id=365" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c88612f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinProxy version 6.1a or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for evidence of WinProxy.
name = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/WinProxy 6/DisplayName");
if (name && name =~ "^WinProxy \(Version ([0-5]\.|6\.0)") {
  security_hole(0);
  exit(0);
}

