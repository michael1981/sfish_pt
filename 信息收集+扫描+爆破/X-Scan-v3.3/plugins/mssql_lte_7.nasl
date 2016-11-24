#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if(description)
{
 script_id(11870);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2000-0199");
 script_bugtraq_id(1055);
 script_xref(name:"OSVDB", value:"10155");

 script_name(english:"Microsoft SQL Server < 7 Local Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SQL Server is affected by a local privilege escalation 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"Based on version number, the remote host may be vulnerable to a local
exploit wherein authenticated user can obtain and crack SQL username 
and password from the registry

An attacker may use this flaw to elevate their privileges on the local
database.

*** This alert might be a false positive, as Nessus did not actually
*** check for this flaw but solely relied on the presence of MS SQL 7 to
*** issue this alert" );
 script_set_attribute(attribute:"see_also", value:"http://www.iss.net/threats/advise45.html" );
 script_set_attribute(attribute:"solution", value:
"Ensure that the configuration has enabled Always prompting for 
login name and password" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Microsoft SQL less than or equal to 7 may be misconfigured");
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_require_ports(1433, "Services/mssql");
 script_dependencie("mssqlserver_detect.nasl", "mssql_version.nasl"); 
 exit(0);
}

port=1433;
version = get_kb_item("mssql/SQLVersion");
if(version)
{
 if (egrep(pattern:"^[67]\..*" , string:version)) security_warning(port);
}
