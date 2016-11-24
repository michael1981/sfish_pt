#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26914);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-5082", "CVE-2007-5083", "CVE-2007-5084");
  script_bugtraq_id(25823);
  script_xref(name:"OSVDB", value:"41363");
  script_xref(name:"OSVDB", value:"41364");
  script_xref(name:"OSVDB", value:"41365");

  script_name(english:"BrightStor Hierarchical Storage Manager < r11.6 Multiple Remote Vulnerabilities");
  script_summary(english:"Checks version reported by CsAgent");

 script_set_attribute(attribute:"synopsis", value:
"The remote data migration service is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its engine build, the installation of BrightStor
Hierarchical Storage Manager on the remote host has multiple
vulnerabilities affecting its CsAgent service, including buffer
overflows and SQL injection vulnerabilities.  An unauthenticated
remote attacker may be able to leverage these issues to run arbitrary
SQL commands, crash the affected service, or even execute arbitrary
code with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=601" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-09/0385.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-10/0027.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-10/0028.html" );
 script_set_attribute(attribute:"see_also", value:"http://supportconnectw.ca.com/public/bstorhsm/infodocs/bstorhsm-secnot.asp" );
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/securityadvisor/newsinfo/collateral.aspx?cid=156444" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BrightStor Hierarchical Storage Manager r11.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("csagent_udp_detect.nasl");
  script_require_ports("Services/udp/hsm_csagent");

  exit(0);
}


port = get_kb_item("Services/udp/hsm_csagent");
if (!port) exit(0);


# There's a problem if the build uses a date before 2007.
build = get_kb_item("Services/hsm_csagent/" + port + "/build");
if (
  build && 
  build =~ "^[0-9]+ +[01][0-9]/[0-3][0-9]/(1[099]{3}|200[0-6])$"
) {
 security_hole(port:port, protocol:"udp");
 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

