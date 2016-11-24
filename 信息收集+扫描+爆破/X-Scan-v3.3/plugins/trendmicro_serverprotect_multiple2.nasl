#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) 
{
 script_id(25925);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2007-4218", "CVE-2007-4219", "CVE-2007-4731");
 script_bugtraq_id(25395, 25396, 25595);
 script_xref(name:"OSVDB", value:"39750");
 script_xref(name:"OSVDB", value:"39751");
 script_xref(name:"OSVDB", value:"39752");
 script_xref(name:"OSVDB", value:"39753");
 script_xref(name:"OSVDB", value:"39754");
 script_xref(name:"OSVDB", value:"45878");

 script_name(english:"Trend Micro ServerProtect Multiple Remote Overflows");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host through the AntiVirus
Agent." );
 script_set_attribute(attribute:"description", value:
"The remote version of Trend Micro ServerProtect is vulnerable to
multiple buffer overflows in the RPC interface.  By sending specially
crafted requests to the remote host, an attacker may be able to
exploit those overflows and execute arbitrary code on the remote host
with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=587" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=588" );
 script_set_attribute(attribute:"solution", value:
"Trend Micro has released a patch for ServerProtect for Windows/NetWare:

http://www.trendmicro.com/download/product.asp?productid=17" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 script_summary(english:"Checks for ServerProtect version");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_require_ports(5168);
 script_dependencies ("trendmicro_serverprotect_detect.nasl");
 script_require_keys ("Antivirus/TrendMicro/ServerProtect");
 exit(0);
}

version = get_kb_item ("Antivirus/TrendMicro/ServerProtect");

if (!version)
  exit (0);

port = 5168;

v = split (version, sep:".", keep:FALSE);

if ( (v[0] < 5) ||
     (v[0] == 5 && v[1] < 58) ||
     (v[0] == 5 && v[1] == 58 && v[2] == 0 && v[3] < 1185) )
  security_hole(port:port);
