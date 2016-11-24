#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18257);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-1009", "CVE-2005-1547");
  script_bugtraq_id(12967, 13594, 13618);
  script_xref(name:"OSVDB", value:"15233");
  script_xref(name:"OSVDB", value:"15234");
  script_xref(name:"OSVDB", value:"16602");

  script_name(english:"BakBone NetVault < 7.1.2 / 7.3.1 Multiple Remote Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote backup server is affected by multiple overflow flaws." );
 script_set_attribute(attribute:"description", value:
"The installed version of BakBone NetVault on the remote host suffers
from two remote heap buffer overflow vulnerabilities.  An attacker may
be able to exploit this flaw and execute arbitrary code with SYSTEM
privileges on the affected machine." );
 script_set_attribute(attribute:"see_also", value:"http://www.hat-squad.com/en/000164.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0133.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0167.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.bakbone.com/docs/NetVault_Release_Notes_(712).pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.bakbone.com/docs/NetVault_Release_Notes_(731).pdf" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BackBone NetVault 7.1.2 / 7.3.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_summary(english:"Checks for remote heap overflow vulnerabilities in BakBone NetVault");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("netvault_detect.nasl");
  script_require_ports("Services/nvpmgr");

  exit(0);
}


port = get_kb_item("Services/nvpmgr");
if (!get_port_state(port)) exit(0);


# Get the version number of NetVault on the remote.
nvver = get_kb_item("NetVault/"+port+"/NVVersion");
nvbuild = get_kb_item("NetVault/"+port+"/NVBuild");
if (isnull(nvver) || isnull(nvbuild)) exit(0);

ver = string(nvver[0], ".", nvver[2], nvver[3], " Build ", nvbuild);
if (ver =~ "^(6\.|7\.(0\.|1\.[01]|3\.0))") security_hole(port);
