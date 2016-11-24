#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(33444);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-0085", "CVE-2008-0086", "CVE-2008-0106", "CVE-2008-0107");
 script_bugtraq_id(30082, 30083, 30118, 30119);
 script_xref(name:"OSVDB", value:"46770");
 script_xref(name:"OSVDB", value:"46771");
 script_xref(name:"OSVDB", value:"46772");
 script_xref(name:"OSVDB", value:"46773");

 name["english"] = "MS08-040: Vulnerabilities in Microsoft SQL Server Could Allow Elevation of Privilege (941203)";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is vulnerable to memory corruption flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft SQL Server, Desktop
Engine or Internal Database which is vulnerable to multiple memory
corruption issues. 

These vulnerabilities may allow an attacker to elevate his privileges
on the SQL server." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 7, 2000 and 2005 :

http://www.microsoft.com/technet/security/bulletin/ms08-040.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Determines the version of SQL Server";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl");
 script_require_keys("SMB/Registry/Enumerated", "mssql/path");
 script_require_ports(139, 445, 1433, "Services/mssql");
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


rootfile = get_kb_item("mssql/path");
if ( ! rootfile ) exit(0);
if ( ! is_accessible_share() ) exit(0);

if ( ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2000.80.2050.0", min_version:"2000.80.2000.0") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2000.80.2273.0", min_version:"2000.80.2200.0") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2000.99.4.0", min_version:"2000.90.0.0") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3068.0", min_version:"2005.90.3000.0") == HCF_OLDER ) ||
     ( hotfix_check_fversion(path:rootfile, file:"Sqlservr.exe", version:"2005.90.3233.0", min_version:"2005.90.3200.0") == HCF_OLDER ) )
 {
 set_kb_item(name:"SMB/Missing/MS08-040", value:TRUE);
 hotfix_security_hole();
 }

hotfix_check_fversion_end();
