#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33128);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-2154", "CVE-2008-3852", "CVE-2008-3854", "CVE-2008-3855", "CVE-2008-3856", "CVE-2008-3857", "CVE-2008-6821");
  script_bugtraq_id(29601, 35408, 35409);
  script_xref(name:"OSVDB", value:"46262");
  script_xref(name:"OSVDB", value:"46263");
  script_xref(name:"OSVDB", value:"46264");
  script_xref(name:"OSVDB", value:"46265");
  script_xref(name:"OSVDB", value:"46266");
  script_xref(name:"OSVDB", value:"46267");
  script_xref(name:"OSVDB", value:"46270");
  script_xref(name:"OSVDB", value:"46271");
  script_xref(name:"OSVDB", value:"48429");
  script_xref(name:"Secunia", value:"30558");

  script_name(english:"DB2 < 9 Fix Pack 5 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of DB2 on the remote host
is affected by one or more of the following issues :

  - There is an unspecified security vulnerability
    related to a 'DB2FMP' process (IZ20352).

  - On Windows, the 'DB2FMP' process is running with OS
    privileges (JR30026).

  - The CLR stored procedure deployment feature of IBM 
    Database Add-Ins for Visual Studio can be used to
    escalate privileges or launch a denial of service
    attack against a DB2 server (JR28432).

  - The password used to connect to the database can be
    seen in plaintext in a memory dump (JR27422).

  - There is a possible stack variable overrun in
    'SQLRLAKA()' (IZ16346).

  - A local privilege escalation vulnerability via file
    creation can result in root-level access (IZ12735).

  - There are possible buffer overflows involving 'XQUERY', 
    'XMLQUERY', 'XMLEXISTS', and 'XMLTABLE' (IZ18434).

  - A specially crafted client CONNECT request could
    crash the server (IZ07299).

  - There is an unspecified remote buffer overflow in
    DAS server code (IZ22188).

  - INSTALL_JAR can be used to create or overwrite
    critical system files (IZ21983)." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496406/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496405/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255607" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ20352" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1JR30026" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1JR28432" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ12735" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1JR27422" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ16346" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ18434" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ07299" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ22188" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ21983" );
 script_set_attribute(attribute:"solution", value:
"Apply DB2 Version 9 Fix Pack 5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
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
      is_level_older(lvl:level, base:"9.1.500.555", min:"9.0.0.0")
    ) ||
    # Linux, x86, 2.6 kernel
    (
      platform == 18 && 
      is_level_older(lvl:level, base:"9.1.0.5", min:"9.0.0.0")
    )
  ) security_hole(port);
}
