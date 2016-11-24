#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(35110);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-1391", "CVE-2008-3170", "CVE-2008-3623", "CVE-2008-4217", "CVE-2008-4220",
                "CVE-2008-4221", "CVE-2008-4222", "CVE-2008-4224", "CVE-2008-4818", "CVE-2008-4819",
                "CVE-2008-4820", "CVE-2008-4821", "CVE-2008-4822", "CVE-2008-4823", "CVE-2008-4824");
  script_bugtraq_id(28479, 30192, 32129, 32291, 32881, 32872, 32874, 32876, 32877);
  script_xref(name:"OSVDB", value:"47275");
  script_xref(name:"OSVDB", value:"49753");
  script_xref(name:"OSVDB", value:"49780");
  script_xref(name:"OSVDB", value:"49781");
  script_xref(name:"OSVDB", value:"49783");
  script_xref(name:"OSVDB", value:"49785");
  script_xref(name:"OSVDB", value:"49790");
  script_xref(name:"OSVDB", value:"49939");
  script_xref(name:"OSVDB", value:"50923");
  script_xref(name:"OSVDB", value:"50924");
  script_xref(name:"OSVDB", value:"50925");

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2008-008)");
  script_summary(english:"Check for the presence of Security Update 2008-008");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.4 that does not
have Security Update 2008-008 applied. 

This security update contains fixes for the following products :

  - BOM
  - CoreGraphics
  - CoreServices
  - Flash Player Plug-in
  - Libsystem
  - network_cmds
  - UDF" );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3338" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Dec/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Install Security Update 2008-008 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");
  exit(0);
}

#

uname = get_kb_item("Host/uname");
if (!uname) exit(0);

if (egrep(pattern:"Darwin.* (8\.[0-9]\.|8\.1[01]\.)", string:uname))
{
  packages = get_kb_item("Host/MacOSX/packages");
  if (!packages) exit(0);

  if (!egrep(pattern:"^SecUpd(Srvr)?(2008-008|2009-|20[1-9][0-9]-)", string:packages))
    security_hole(0);
}
