#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34195);
  script_version("$Revision: 1.7 $");

  script_cve_id(
    "CVE-2008-2154",
    "CVE-2008-3856",
    "CVE-2008-3958",
    "CVE-2008-3960",
    "CVE-2008-6820",
    "CVE-2008-6821"
  );
  script_bugtraq_id(31058, 35408, 35409);
  script_xref(name:"Secunia", value:"31787");
  script_xref(name:"OSVDB", value:"46262");
  script_xref(name:"OSVDB", value:"48144");
  script_xref(name:"OSVDB", value:"48146");
  script_xref(name:"OSVDB", value:"48147");
  script_xref(name:"OSVDB", value:"48148");
  script_xref(name:"OSVDB", value:"48149");
  script_xref(name:"OSVDB", value:"49949");

  script_name(english:"DB2 8 < Fix Pack 17 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of DB2 8 on the remote host
is affected by multiple issues :

  - By sending malicious DB2 UDB v7 client CONNECT/DETACH
    requests it may be possible to crash the remote DB2 
    server. (IZ08134)

  - Failure to switch the owner of the 'DB2FMP' process
    may lead to a security vulnerability on Unix / Linux
    platforms. (IZ20350)

  - DAS server code is affected by a buffer overflow 
    vulnerability. (IZ22004)

  - Using INSTALL_JAR, it may be possible to create and 
    overwrite critical files on the system. (IZ22142)

  - DB2 does not mark inoperative or drop views and triggers
    if the definer cannot maintain the objects. (IZ22287)

  - By sending malicious packets to 'DB2JDS', it may be 
    possible to crash the remote DB2 server. (JR29274)

  - While running on Windows 'DB2FMP' runs with OS
    privileges. (JR30228)" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255352" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ08134" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ20350" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22004" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22142" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22287" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR29274" );
 script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR30228" );
 script_set_attribute(attribute:"solution", value:
"Apply DB2 UDB Version 8 FixPak 17 or later." );
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
    (platform ==  5 && is_level_older(lvl:level, base:"8.1.17.644")) ||
    # Linux, x86, 2.6 kernel
    (platform == 18 && is_level_older(lvl:level, base:"8.1.2.152"))
  ) security_hole(port);
}
