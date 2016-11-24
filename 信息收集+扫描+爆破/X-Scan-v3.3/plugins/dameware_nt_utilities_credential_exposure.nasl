#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18117);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-1166");
  script_bugtraq_id(13200);
  script_xref(name:"OSVDB", value:"15275");

  name["english"] = "DameWare NT Utilities Authentication Credentials Persistence Weakness";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the copy of DameWare NT Utilities
installed on the remote host allows a local user to recover
authentication credentials because it stores sensitive information
such as username, password, remote user, and remote hostname in memory
as plain text." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0225.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.dameware.com/support/security/bulletin.asp?ID=SB5" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to DameWare NT Utilities 3.80 / 4.9 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for authentication credentials persistence weakness in DameWare NT Utilities";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for the version of DameWare NT Utilities installed.
key1 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{531C5E56-31E1-4797-AACB-2B17DE8A35D2}/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{531C5E56-31E1-4797-AACB-2B17DE8A35D2}/DisplayVersion";
if (get_kb_item(key1)) {
  ver = get_kb_item(key2);
  # nb: the advisory claims versions 4.9 and below are vulnerable.
  if (ver && ver =~ "^([0-3]|4\.([0-8]|9\.0\.0$))") security_note(get_kb_item("/SMB/transport"));
}
