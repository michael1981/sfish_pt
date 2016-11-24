#
# (C) Tenable Network Security, Inc.
#
	       

include("compat.inc");

if(description)
{
 script_id(11804);
 script_version ("$Revision: 1.19 $");

 script_cve_id("CVE-2003-0230", "CVE-2003-0231", "CVE-2003-0232");
 script_bugtraq_id(8274, 8275, 8276);
 script_xref(name:"OSVDB", value:"2299");
 script_xref(name:"OSVDB", value:"10123");
 script_xref(name:"OSVDB", value:"10125");

 name["english"] = "MS03-031: Cumulative Patch for MS SQL Server (815495)";
 script_name(english:name["english"]);
  
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the SQL
service." );
 script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL server is vulnerable to several flaws :

  - Named pipe hijacking
  - Named Pipe Denial of Service
  - SQL server buffer overrun

These flaws may allow a user to gain elevated privileges on this host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for MSSQL 7 and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms03-031.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


 summary["english"] = "Microsoft's SQL Version Query";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);

 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

path = hotfix_get_mssqldir();
if (!path)
  exit (0);

if (is_accessible_share ())
{
 if ( ( hotfix_check_fversion(path:path, file:"sqlrepss.dll", version:"2000.80.765.0", min_version:"2000.80.0.0") == HCF_OLDER ) ||
      ( hotfix_check_fversion(path:path, file:"ums.dll", version:"2000.33.25.0", min_version:"2000.33.0.0") == HCF_OLDER ) )
 {
 set_kb_item(name:"SMB/Missing/MS03-031", value:TRUE);
 hotfix_security_warning();
 }

 hotfix_check_fversion_end();
}
