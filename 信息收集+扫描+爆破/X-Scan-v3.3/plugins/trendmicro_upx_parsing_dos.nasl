#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24815);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-1591");
  script_bugtraq_id(22965);
  script_xref(name:"OSVDB", value:"34075");

  script_name(english:"Trend Micro VsapiNT.sys UPX File Parsing DoS");
  script_summary(english:"Checks version of virus pattern file");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The version of Trend Micro AntiVirus installed on the remote Windows
host contains a divide-by-zero error in its 'VsapiNT.sys' kernel
driver.  Using a specially-crafted UPX file, a remote attacker may be
able to leverage this flaw to crash the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=488" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/462798/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://esupport.trendmicro.com/support/viewxml.do?ContentID=EN-1034587" );
 script_set_attribute(attribute:"solution", value:
"Update the Virus Pattern File to 4.335.00 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_installed.nasl");
  script_require_keys("Antivirus/TrendMicro/trendmicro_internal_pattern_version");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");

pats = get_kb_item("Antivirus/TrendMicro/trendmicro_internal_pattern_version");
if (!isnull(pats) && int(pats) < 433500)
{
  report = string(
    "\n",
    "Nessus has determined that the current Virus Pattern File on the remote\n",
    "host is version ", pats, ".\n"
  );
  security_hole(port:get_kb_item("SMB/transport"), extra:report);
}
