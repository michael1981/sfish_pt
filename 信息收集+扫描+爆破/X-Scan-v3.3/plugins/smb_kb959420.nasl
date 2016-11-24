#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35635);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-5416");
  script_bugtraq_id(32710);
  script_xref(name:"OSVDB", value:"50589");

  script_name(english:"MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) (uncredentialed check)");
  script_summary(english:"Determines the version of SQL Server");

  script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host through SQL Server");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft SQL Server, Desktop
Engine or Internal Database that suffers from an authenticated remote
code execution vulnerability in the MSSQL extended stored procedure
'sp_replwritetovarbin' due to an invalid parameter check. 

Successful exploitation could allow an attacker to take complete
control of the affected system.");
 script_set_attribute(attribute:"solution", value:"
Microsoft has released a set of patches for SQL Server 2000 and 2005 :

http://www.microsoft.com/technet/security/Bulletin/MS09-004.mspx");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_dependencies("mssqlserver_detect.nasl");
 script_require_keys("MSSQL/Version");
 script_require_ports(1433, "Services/mssql");
 exit(0);
}

#

v = get_kb_item("MSSQL/Version");
if (!v) exit(0);

port = get_kb_item("Services/mssql");
if (!port) port = 1433;

v = split(v, sep:".", keep:FALSE);

if ( 
     # (v[0] == 8 && v[1] == 0 && v[2] < 2055) ||
     (int(v[0]) == 9 && int(v[1]) == 0 && int(v[2]) < 3077) 
   )
  security_hole(port);
