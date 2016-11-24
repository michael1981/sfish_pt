#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) 
{
 script_id(24680);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2007-1070");
 script_bugtraq_id(22639);
 script_xref(name:"OSVDB", value:"33042");

 script_name(english:"Trend Micro ServerProtect TmRpcSrv.dll RPC Request Multiple Overflows");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host through the AntiVirus
Agent." );
 script_set_attribute(attribute:"description", value:
"The remote version of Trend Micro ServerProtect is vulnerable to
multiple stack overflows in the RPC interface.  By sending specially
crafted requests to the remote host, an attacker may be able to
exploit stack based overflows and execute arbitrary code on the remote
host." );
 script_set_attribute(attribute:"see_also", value:"http://www.tippingpoint.com/security/advisories/TSRT-07-01.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.tippingpoint.com/security/advisories/TSRT-07-02.html" );
 script_set_attribute(attribute:"solution", value:
"Trend Micro has released a patch for ServerProtect for Windows/NetWare:

http://www.trendmicro.com/download/product.asp?productid=17" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 script_summary(english:"Checks for ServerProtect version");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
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
     (v[0] == 5 && v[1] == 58 && v[2] == 0 && v[3] < 1171) )
  security_hole(port:port);
