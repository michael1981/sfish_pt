#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35632);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-5416");
  script_bugtraq_id(32710);
  script_xref(name:"OSVDB", value:"50589");

  script_name(english: "MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420)");
  script_summary(english:"Determines the version of SQL Server");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through SQL Server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft SQL Server, Desktop
Engine or Internal Database that suffers from an authenticated remote
code execution vulnerability in the MSSQL extended stored procedure
'sp_replwritetovarbin' due to an invalid parameter check. 

Successful exploitation could allow an attacker to take complete
control of the affected system." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2000 and 2005 :

http://www.microsoft.com/technet/security/Bulletin/MS09-004.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl");
  script_require_keys("SMB/Registry/Enumerated", "mssql/path");
  script_require_ports(139, 445, 1433, "Services/mssql");

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


rootfile = get_kb_item("mssql/path");
if (!rootfile) exit(0);
if (!is_accessible_share()) exit(0);


if (
  (hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2000.80.2055.0", min_version:"2000.80.2000.0") == HCF_OLDER) ||
  (hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2000.80.2282.0", min_version:"2000.80.2200.0") == HCF_OLDER) ||
  (hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3077.0", min_version:"2005.90.3000.0") == HCF_OLDER) ||
  (hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3310.0", min_version:"2005.90.3200.0") == HCF_OLDER)
) {
 set_kb_item(name:"SMB/Missing/MS09-004", value:TRUE);
 hotfix_security_hole();
 }

hotfix_check_fversion_end();
