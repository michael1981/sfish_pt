#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24240);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-0449", "CVE-2007-0672", "CVE-2007-0673");
  script_bugtraq_id(22199, 22337, 22339, 22340, 22342);
  script_xref(name:"OSVDB", value:"31593");
  script_xref(name:"OSVDB", value:"32948");
  script_xref(name:"OSVDB", value:"32949");

  script_name(english:"CA BrightStor ARCserve Backup for Laptops & Desktops Server Multiple Vulnerabilities (QO83833)");
  script_summary(english:"Checks version of BrightStor ARCserve Backup for Laptops & Desktops Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote backup server software is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of BrightStor ARCserve
Backup for Laptops & Desktops Server on the remote host is affected by
multiple buffer overflows and denial of service vulnerabilities that
can be exploited by a remote attacker to execute arbitrary code on the
affected host with LOCAL SYSTEM privileges or to crash the associated
services." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-01/0683.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-01/0684.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-01/0686.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-01/0687.html" );
 script_set_attribute(attribute:"see_also", value:"http://supportconnectw.ca.com/public/sams/lifeguard/infodocs/babldimpsec-notice.asp" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-01/0470.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as described in the vendor advisory
referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("arcserve_lgserver_admin_detect.nasl");
  script_require_keys("ARCSERVE/LGServer/Version");

  exit(0);
}


ver = get_kb_item("ARCSERVE/LGServer/Version");
if (isnull(ver)) exit(0);


matches = eregmatch(string:ver, pattern:"^([0-9]+\.[0-9]+)\.([0-9]+)$");
if (!isnull(matches))
{
  ver = matches[1];
  build = int(matches[2]);

  if (
    (ver == "11.1" && build < 900) ||
    # nb: QI85497 says there's no patch for 11.0; the solution is to 
    #     upgrade to 11.1 and then apply BABLD r11.1 SP2.
    (ver == "11.0") ||
    # nb: QO85402 doesn't exist.
    (ver == "4.0")
  )
  {
    # Issue a report for each open port used by the server.
    port = get_kb_item("Services/lgserver");
    if (port && get_tcp_port_state(port)) security_hole(port);

    port = get_kb_item("Services/lgserver_admin");
    if (port && get_tcp_port_state(port)) security_hole(port);
  }
}
