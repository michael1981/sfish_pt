#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34056);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2008-2154", "CVE-2008-3852", "CVE-2008-4693", "CVE-2008-4692", "CVE-2008-6821");
  script_bugtraq_id(30859, 35408, 35409);
  script_xref(name:"OSVDB", value:"46270");
  script_xref(name:"OSVDB", value:"49949");
  script_xref(name:"OSVDB", value:"49950");
  script_xref(name:"Secunia", value:"31635");

  script_name(english:"DB2 9.5 < Fix Pack 2 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The installation of DB2 9.5 on the remote host does not have Fix Pack
2 applied, and hence it may be affected by the following issues :

  - DB2 does not mark inoperative or drop views and triggers
    if the definer cannot maintain the objects (IZ22307).

  - Password-related connection string keyword values may
    appear in trace output (IZ28489).

  - There is an unspecified vulnerability in the way CLR 
    Stored Procedures for Visual Studio from IBM database 
    add-ins are deployed (JR28431). 

  - There is an unspecified buffer overflow in DAS server
    code (IZ22190).

  - INSTALL_JAR can be used to create or overwrite critical
    files on a system (IZ22143).

  - On Windows, the db2fmp process is running with OS
    privileges (JR30227)." );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21293566" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22307" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ28489" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR28431" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22190" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22143" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR30227" );
 script_set_attribute(attribute:"solution", value:
"Apply DB2 Version 9.5 Fix Pack 2." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}


port = get_kb_item("Services/db2das");
if (!port) port = 523;
if (!get_port_state(port)) exit(0);


# Make sure the port is really open.
soc = open_sock_tcp(port);
if (!soc) exit(0);
close(soc);


function is_level_older(lvl, base, min)
{
  if (isnull(lvl) || isnull(base)) return NULL;

  local_var i, v1, v2, vmin;

  v1 = split(lvl, sep:'.', keep:0);
  v2 = split(base, sep:'.', keep:0);
  if (isnull(min)) vmin = make_list(0,0,0,0);
  else vmin = split(min, sep:'.', keep:0);

  v1 = make_list(int(v1[0]), int(v1[1]), int(v1[2]), int(v1[3]));
  v2 = make_list(int(v2[0]), int(v2[1]), int(v2[2]), int(v2[3]));
  vmin = make_list(int(vmin[0]), int(vmin[1]), int(vmin[2]), int(vmin[3]));

  for (i=0; i<max_index(v1); i++)
    if (v1[i] < v2[i])
    {
      if (v1[i] < vmin[i]) return FALSE;
      else return TRUE;
    }
    else if (v1[i] > v2[i]) return FALSE;

  return FALSE;
}


platform = get_kb_item("DB2/" + port + "/Platform");
level = get_kb_item("DB2/" + port + "/Level");
if (platform && level)
{
  if (
    # Windows, x86
    (
      platform == 5 && 
      is_level_older(lvl:level, base:"9.5.200.315", min:"9.5.0.0")
    ) ||
    # Linux, x86, 2.6 kernel
    (
      platform == 18 && 
      is_level_older(lvl:level, base:"9.5.0.2", min:"9.5.0.0")
    )
  ) security_hole(port);
}
