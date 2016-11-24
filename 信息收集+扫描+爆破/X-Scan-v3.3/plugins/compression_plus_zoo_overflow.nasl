#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22308);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-4554");
  script_bugtraq_id(19796);
  script_xref(name:"OSVDB", value:"28371");

  script_name(english:"Compression Plus CP5DLL32.DLL ZOO Archive Header Processing Overflow");
  script_summary(english:"Checks version of Compression Plus' cp5dll32.dll");

 script_set_attribute(attribute:"synopsis", value:
"There is a library file installed on the remote Windows host that is
affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the Compression Plus toolkit installed on the remote
host contains a DLL that reportedly is prone to a stack-based overflow
when processing specially-crafted ZOO files.  Exploitation depends on
how the toolkit is used, especially with third-party products." );
 script_set_attribute(attribute:"see_also", value:"http://www.mnin.org/advisories/2006_cp5_tweed.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.becubed.com/downloads/compfix.txt" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix or upgrade Cp5dll32.dll to version
5.0.1.28 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


sys_root = hotfix_get_systemroot();
if (!sys_root || !is_accessible_share()) exit(0);

if (
  hotfix_check_fversion(
    file    : "Cp5dll32.dll", 
    path    : sys_root + "\system32", 
    version : "5.0.1.28"
  ) == HCF_OLDER
) security_warning(get_kb_item("SMB/transport"));
hotfix_check_fversion_end();

