#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3004) exit(0);



include("compat.inc");

if (description)
{
  script_id(35111);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-1391", "CVE-2008-3170", "CVE-2008-3623", "CVE-2008-4217", "CVE-2008-4218",
                "CVE-2008-4219", "CVE-2008-4220", "CVE-2008-4221", "CVE-2008-4222", "CVE-2008-4223",
                "CVE-2008-4224", "CVE-2008-4234", "CVE-2008-4236", "CVE-2008-4237", "CVE-2008-4818",
                "CVE-2008-4819", "CVE-2008-4820", "CVE-2008-4821", "CVE-2008-4822", "CVE-2008-4823",
                "CVE-2008-4824");
  script_bugtraq_id(28479, 30192, 32129, 32291, 32870, 32872, 32873, 32874, 32875, 32876, 
                    32877, 32879, 32880, 32881);
  script_xref(name:"OSVDB", value:"47275");
  script_xref(name:"OSVDB", value:"49753");
  script_xref(name:"OSVDB", value:"49780");
  script_xref(name:"OSVDB", value:"49781");
  script_xref(name:"OSVDB", value:"49783");
  script_xref(name:"OSVDB", value:"49785");
  script_xref(name:"OSVDB", value:"49790");
  script_xref(name:"OSVDB", value:"49939");
  script_xref(name:"OSVDB", value:"50861");
  script_xref(name:"OSVDB", value:"50923");
  script_xref(name:"OSVDB", value:"50924");
  script_xref(name:"OSVDB", value:"50925");
  script_xref(name:"OSVDB", value:"50982");
  script_xref(name:"OSVDB", value:"53100");

  script_name(english:"Mac OS X < 10.5.6 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes various
security issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.5 that is older
than version 10.5.6. 

Mac OS X 10.5.6 contains security fixes for the following products :

  - ATS
  - BOM
  - CoreGraphics
  - CoreServices
  - CoreTypes
  - Flash Player Plug-in
  - Kernel
  - Libsystem
  - Managed Client
  - network_cmds
  - Podcast Producer
  - UDF" );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3338" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2008/Dec/msg00000.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X 10.5.6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os) os = get_kb_item("Host/OS");
if (!os) exit(0);

if (ereg(pattern:"Mac OS X 10\.5\.[0-5]([^0-9]|$)", string:os)) 
  security_hole(0);
