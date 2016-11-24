#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(31605);
  script_version ("$Revision: 1.19 $");

  script_cve_id("CVE-2005-3352", "CVE-2005-4077", "CVE-2006-3334", "CVE-2006-3747", "CVE-2006-5793",
                "CVE-2006-6481", "CVE-2007-0897", "CVE-2007-0898", "CVE-2007-1659", "CVE-2007-1660",
                "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-1745", "CVE-2007-1997", "CVE-2007-2445",
                "CVE-2007-2799", "CVE-2007-3378", "CVE-2007-3725", "CVE-2007-3799", "CVE-2007-3847",
                "CVE-2007-4510", "CVE-2007-4560", "CVE-2007-4568", "CVE-2007-4752", "CVE-2007-4766",
                "CVE-2007-4767", "CVE-2007-4768", "CVE-2007-4887", "CVE-2007-4990", "CVE-2007-5000",
                "CVE-2007-5266", "CVE-2007-5267", "CVE-2007-5268", "CVE-2007-5269", "CVE-2007-5795",
                "CVE-2007-5901", "CVE-2007-5958", "CVE-2007-5971", "CVE-2007-6109", "CVE-2007-6203",
                "CVE-2007-6335", "CVE-2007-6336", "CVE-2007-6337", "CVE-2007-6388", "CVE-2007-6421",
                "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0005", "CVE-2008-0006",
                "CVE-2008-0044", "CVE-2008-0045", "CVE-2008-0046", "CVE-2008-0047", "CVE-2008-0048",
                "CVE-2008-0049", "CVE-2008-0050", "CVE-2008-0051", "CVE-2008-0052", "CVE-2008-0053",
                "CVE-2008-0054", "CVE-2008-0055", "CVE-2008-0056", "CVE-2008-0057", "CVE-2008-0058",
                "CVE-2008-0059", "CVE-2008-0060", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0318",
                "CVE-2008-0596", "CVE-2008-0728", "CVE-2008-0882", "CVE-2008-0987", "CVE-2008-0988",
                "CVE-2008-0989", "CVE-2008-0990", "CVE-2008-0992", "CVE-2008-0993", "CVE-2008-0994",
                "CVE-2008-0995", "CVE-2008-0996", "CVE-2008-0997", "CVE-2008-0998", "CVE-2008-0999",
                "CVE-2008-1000");
  script_bugtraq_id(19204, 21078, 24268, 25398, 25439, 25489, 25498, 26346, 26750, 26838,
                    26927, 26946, 27234, 27236, 27751, 27988, 28278, 28303, 28304, 28307,
                    28320, 28323, 28334, 28339, 28340, 28341, 28343, 28344, 28345, 28357,
                    28358, 28359, 28363, 28364, 28365, 28367, 28368, 28371, 28371, 28372,
                    28374, 28375, 28384, 28385, 28386, 28387, 28388, 28389);
  script_xref(name:"OSVDB", value:"36855");
  script_xref(name:"OSVDB", value:"36869");
  script_xref(name:"OSVDB", value:"36909");
  script_xref(name:"OSVDB", value:"36910");
  script_xref(name:"OSVDB", value:"36911");
  script_xref(name:"OSVDB", value:"37051");
  script_xref(name:"OSVDB", value:"39134");
  script_xref(name:"OSVDB", value:"40263");
  script_xref(name:"OSVDB", value:"40759");
  script_xref(name:"OSVDB", value:"40760");
  script_xref(name:"OSVDB", value:"40766");
  script_xref(name:"OSVDB", value:"42158");
  script_xref(name:"OSVDB", value:"42214");
  script_xref(name:"OSVDB", value:"42294");
  script_xref(name:"OSVDB", value:"42295");
  script_xref(name:"OSVDB", value:"42296");
  script_xref(name:"OSVDB", value:"42297");
  script_xref(name:"OSVDB", value:"43345");
  script_xref(name:"OSVDB", value:"43346");
  script_xref(name:"OSVDB", value:"43390");
  script_xref(name:"OSVDB", value:"43391");
  script_xref(name:"OSVDB", value:"43392");
  script_xref(name:"OSVDB", value:"43393");
  script_xref(name:"OSVDB", value:"43394");
  script_xref(name:"OSVDB", value:"43395");
  script_xref(name:"OSVDB", value:"43396");
  script_xref(name:"OSVDB", value:"43397");
  script_xref(name:"OSVDB", value:"43398");
  script_xref(name:"OSVDB", value:"43399");
  script_xref(name:"OSVDB", value:"43400");
  script_xref(name:"OSVDB", value:"43406");
  script_xref(name:"OSVDB", value:"43546");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2008-002)");
  script_summary(english:"Check for the presence of Security Update 2008-002");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 or 10.4 that
does not have the security update 2008-002 applied. 

This update contains several security fixes for a number of programs." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307562" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Mar/msg00001.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/14242" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2008-002 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");
  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(0);

if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages");
  if (!packages) exit(0);

  if (!egrep(pattern:"^SecUpd(Srvr)?(2008-00[2-8]|2009-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
else if (egrep(pattern:"Darwin.* (9\.[0-2]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(0);

  if (!egrep(pattern:"^com\.apple\.pkg\.update\.security\.2008\.002\.bom", string:packages))
    security_hole(0);
}
