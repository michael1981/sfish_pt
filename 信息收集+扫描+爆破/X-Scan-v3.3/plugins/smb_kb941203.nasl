#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(34311);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2008-0085", "CVE-2008-0086", "CVE-2008-0106", "CVE-2008-0107");
 script_bugtraq_id(30082, 30083, 30118, 30119);
 script_xref(name:"OSVDB", value:"46770");
 script_xref(name:"OSVDB", value:"46771");
 script_xref(name:"OSVDB", value:"46772");
 script_xref(name:"OSVDB", value:"46773");

 script_name(english:"MS08-040: Microsoft SQL Server Multiple Privilege Escalation (941203) (uncredentialed check)");
 script_summary(english:"Checks the version of SQL Server");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote SQL server is vulnerable to memory corruption flaws."
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host is running a version of Microsoft SQL Server, Desktop\n",
   "Engine or Internal Database that is vulnerable to multiple memory\n",
   "corruption issues.\n",
   "\n",
   "These vulnerabilities may allow an attacker to elevate his privileges\n",
   "on the SQL server."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for SQL Server 7, 2000 and\n",
   "2005 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms08-040.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
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
     # (v[0] == 8 && v[1] == 0 && v[2] < 2050) ||
     (int(v[0]) == 9 && int(v[1]) == 0 && int(v[2]) < 3042) 
   )
  security_hole(port);
