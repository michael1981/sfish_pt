#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(30153);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-3676", "CVE-2007-5757", "CVE-2008-0698");
  script_bugtraq_id(27596, 27680, 27681);
  script_xref(name:"OSVDB", value:"41629");
  script_xref(name:"OSVDB", value:"41630");

  script_name(english:"DB2 < 8.1 FixPak 16 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of DB2 on the remote host
is affected by one or more of the following issues :

  - A local user may be able to gain root privileges using
    the 'db2pd' tool (IZ03546).

  - The 'b2dart' tool executes a TPUT command, which
    effectively allows users to run commands as the DB2
    instance owner (IZ03647).

  - A buffer overflow and invalid memory access 
    vulnerability exist in the DAS server code (IZ05496).

  - An unspecified vulnerability in 'SYSPROC.ADMIN_SP_C'
    (IZ06972).

  - An unspecified vulnerability exists due to incorrect
    authorization checking in 'ALTER TABLE' statements
    (IZ07337)." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=653" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=654" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0073.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0074.html" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21256235" );
 script_set_attribute(attribute:"solution", value:
"Apply DB2 UDB Version 8.1 FixPak 16 or later." );
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
    (platform == 5 && is_level_older(lvl:level, base:"8.1.16.429")) ||
    # Linux, x86, 2.6 kernel
    (platform == 18 && is_level_older(lvl:level, base:"8.1.2.144"))
  ) security_hole(port);
}
