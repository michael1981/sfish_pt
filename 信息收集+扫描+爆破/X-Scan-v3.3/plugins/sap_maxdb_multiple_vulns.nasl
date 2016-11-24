#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32194);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-0244", "CVE-2008-0306", "CVE-2008-0307");
  script_bugtraq_id(27206, 28183, 28185);
  script_xref(name:"OSVDB", value:"40210");
  script_xref(name:"OSVDB", value:"43083");
  script_xref(name:"OSVDB", value:"43084");

  script_name(english:"SAP MaxDB Multiple Vulnerabilities");
  script_summary(english:"Checks vulnerable versions of SAP MaxDB");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MaxDB, a database server from SAP.

According to its version, the remote server is affected by a 
multiple flaws. 
 
 - A vulnerability in 'vserver' process could allow an unauthenticated 
   attacker to execute arbitrary code, subject to the privileges of the 
   user under which the process operates. In order to successfully 
   exploit this issue an attacker must have prior knowledge of an active 
   database name on the server.

 - A design error in 'sdbstarter', could allow an attacker to elevate his 
   privileges to root level privileges.

 - A vulnerability in cons.exe could allow command execution before 
   authenticating to the database server." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=669" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=670" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/486039" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SAP MaxDB 7.7.04 Build 08 / 7.7.03 Build 23 / 7.7.02 Build
20 / 7.6.05 Build 02 / 7.6.04 Build 06 / 7.6.03 Build 15 / 7.5.00
Build 48 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("sapdb_detect.nasl");
  script_require_ports("Services/sap_db_vserver", 7210);

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/sap_db_vserver");
if (!port) port = 7210;
if (!get_tcp_port_state(port)) exit(0);

ver = get_kb_item(string("SAPDB/",port,"/BUILD"));
if (!ver) exit(0);

if (!ereg(pattern:"^[A-Za-z]+ *[0-9]+\.[0-9]+\.[0-9]+ *Build [0-9]+\-[0-9]+\-[0-9]+\-[0-9]+$",string: ver)) exit(0);

major_ver = NULL;
minor_ver = NULL;

major_ver = ereg_replace(pattern:"^[A-Za-z]+ *([0-9]+\.[0-9]+\.[0-9]+) *Build [0-9]+\-[0-9]+\-[0-9]+\-[0-9]+$",string:ver,replace:"\1");
minor_ver = ereg_replace(pattern:"^[A-Za-z]+ *[0-9]+\.[0-9]+\.[0-9]+ *Build ([0-9]+)\-[0-9]+\-[0-9]+\-[0-9]+$",string:ver,replace:"\1");


if (!isnull(major_ver) && !isnull(minor_ver))
{
  sap_db_version = string(major_ver,".",minor_ver);
  v = split(sap_db_version, sep:".", keep:FALSE);
  for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

  if ( 
     ( v[0]  < 7                                       ) ||
     ( v[0]  < 7 && v[1] < 5                           ) ||
     ( v[0] == 7 && v[1] == 5 && v[2] == 0 && v[3] < 48) ||
     ( v[0] == 7 && v[1] == 6 && v[2] < 3              ) ||
     ( v[0] == 7 && v[1] == 6 && v[2] == 3 && v[3] < 15) ||
     ( v[0] == 7 && v[1] == 6 && v[2] == 4 && v[3] < 6 ) ||
     ( v[0] == 7 && v[1] == 6 && v[2] == 5 && v[3] < 2 ) ||
     ( v[0] == 7 && v[1] == 7 && v[2] == 2 && v[3] < 20) ||
     ( v[0] == 7 && v[1] == 7 && v[2] == 3 && v[3] < 23) ||
     ( v[0] == 7 && v[1] == 7 && v[2] == 4 && v[3] < 8 ) 
   )
   {
     if (report_verbosity)
     { 	
       report = string(
          "\n",
          "  ",ver , " is installed on the remote host.\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
   }
} 
