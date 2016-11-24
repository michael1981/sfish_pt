#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25905);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2007-2582", "CVE-2007-4270", "CVE-2007-4271", "CVE-2007-4272",
  "CVE-2007-4273", "CVE-2007-4275", "CVE-2007-4276", "CVE-2007-4417", "CVE-2007-4418", "CVE-2007-4423");
  script_bugtraq_id(23890, 25339, 26010);
  script_xref(name:"OSVDB", value:"40973");
  script_xref(name:"OSVDB", value:"40975");
  script_xref(name:"OSVDB", value:"40976");
  script_xref(name:"OSVDB", value:"40977");
  script_xref(name:"OSVDB", value:"40978");
  script_xref(name:"OSVDB", value:"40979");
  script_xref(name:"OSVDB", value:"40980");
  script_xref(name:"OSVDB", value:"40981");
  script_xref(name:"OSVDB", value:"40982");
  script_xref(name:"OSVDB", value:"40983");
  script_xref(name:"OSVDB", value:"40984");
  script_xref(name:"OSVDB", value:"40989");
  script_xref(name:"OSVDB", value:"40990");
  script_xref(name:"OSVDB", value:"40991");
  script_xref(name:"OSVDB", value:"40992");
  script_xref(name:"OSVDB", value:"40993");
  script_xref(name:"OSVDB", value:"40994");

  script_name(english:"DB2 < 9 Fix Pack 3 / 8 FixPak 15 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of DB2 on the remote host
is affected by one or more of the following issues :

  - A local user may be able to overwrite arbitrary files,
    create arbitrary world-writeable directories, or gain root 
    privileges via symlink attacks or specially-crafted 
    environment variables (IY98210 / IY99261).
  - A user may be able to continue to execute a method even 
    once privileges for the method have been revoked (IY88226, 
    version 8 only).
  - There is an unspecified issue allowing for privilege
    elevation when DB2 'execs' executables while running as 
    root (IY98206 / IY98176).
  - There is an unspecified vulnerability related to incorrect
    authorization routines (JR25940, version 8 only).
  - There is an unspecified vulnerability in 
    'AUTH_LIST_GROUPS_FOR_AUTHID' (IZ01828, version 9.1 
    only).
  - There is an unspecified vulnerability in the 'db2licm' and
    'db2pd' tools (IY97922 / IY97936).
  - There is an unspecified vulnerability involving 'db2licd' 
    and the 'OSSEMEMDBG' and 'TRC_LOG_FILE' environment 
    variables (IY98011 / IY98101).
  - There is a buffer overflow involving the 'DASPROF'
    environment variable (IY97346 / IY99311).
  - There is an unspecified vulnerability that can arise 
    during instance and FMP startup (IZ01923 / IZ02067).
  - The DB2JDS service may allow for arbitrary code execution
    without the need for authentication due to a stack
    overflow in an internal sprintf() call (IY97750, version 
    8 only).
  - The DB2JDS service is affected by two denial of service
    issues that can be triggered by packets with an invalid
    LANG parameter or a long packet, which cause the process
    to terminate (version 8 only).

Note that there is currently insufficient information to determine to
what extent the first set of issues overlaps the others." );
 script_set_attribute(attribute:"see_also", value:"http://www.appsecinc.com/resources/alerts/db2/2007-01.shtml" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-08/0313.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-08/0314.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-08/0315.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-08/0316.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-08/0317.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-08/0318.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-08/0319.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-10/0153.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255607" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255352" );
 script_set_attribute(attribute:"solution", value:
"Apply DB2 Version 9 Fix Pack 3 / 8.1 FixPak 15 / 8.2 FixPak 8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 
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
    #   nb: unaffected by IY98210.
    (
      platform == 5 && 
      (
        is_level_older(lvl:level, base:"9.1.300.257", min:"9.0.0.0") ||
        is_level_older(lvl:level, base:"8.1.15.254")
      )
    ) ||
    # Linux, x86, 2.6 kernel
    (
      platform == 18 && 
      (
        is_level_older(lvl:level, base:"9.1.0.3", min:"9.0.0.0") ||
        is_level_older(lvl:level, base:"8.1.2.136")
      )
    )
  ) security_hole(port);
}
