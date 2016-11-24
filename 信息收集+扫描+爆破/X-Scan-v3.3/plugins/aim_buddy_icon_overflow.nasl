#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(18432);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-1891");
  script_bugtraq_id(13880);
  script_xref(name:"OSVDB", value:"17220");

  name["english"] = "AIM Buddy Icon Overflow Vulnerability";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is susceptible to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"According to the Windows registry, the version of AOL Instant
Messenger install on the remote host has an integer overflow in its
GIF parser, 'ateimg32.dll'.  Using a specially crafted GIF file as a
buddy icon, an attacker can reportedly crash the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://security-protocols.com/advisory/sp-x15-advisory.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-06/0032.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-06/0039.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
  summary["english"] = "Checks for buddy icon overflow vulnerability in AIM";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("aim_detect.nasl");
  script_require_keys("AIM/version");

  exit(0);
}


# Test an install.
ver = get_kb_item("AIM/version");
if (ver)
{
  # There's a problem if the newest version is 5.9.3797 or below.
  iver = split(ver, sep:'.', keep:FALSE);
  if (
    int(iver[0]) < 5 ||
    (
      int(iver[0]) == 5 && 
      (
        int(iver[1]) < 9 ||
        (int(iver[1]) == 9 && int(iver[2]) <= 3797)
      )
    )
  ) security_hole(get_kb_item("SMB/transport"));
}
