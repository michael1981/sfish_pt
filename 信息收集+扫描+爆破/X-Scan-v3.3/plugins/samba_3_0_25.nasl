#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25217);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-2444", "CVE-2007-2446", "CVE-2007-2447");
  script_bugtraq_id(23972, 23973, 23974, 24195, 24196, 24197, 24198);
  script_xref(name:"OSVDB", value:"34698");
  script_xref(name:"OSVDB", value:"34699");
  script_xref(name:"OSVDB", value:"34700");
  script_xref(name:"OSVDB", value:"34731");
  script_xref(name:"OSVDB", value:"34732");
  script_xref(name:"OSVDB", value:"34733");

  script_name(english:"Samba < 3.0.25 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Samba");

 script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Samba server installed on
the remote host is affected by multiple buffer overflow and remote
command injection vulnerabilities, which can be exploited remotely, as
well as a local privilege escalation bug." );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2007-2444.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2007-2446.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2007-2447.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 3.0.25 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager");

  exit(0);
}


include("global_settings.inc");


# nb: this check is unreliable since the patches released by samba.org
#     don't update the version.
if (report_paranoia < 2) exit(0);


lanman = get_kb_item("SMB/NativeLanManager");
if("Samba" >< lanman)
{
  if (ereg(pattern:"Samba 3\.0\.([0-9]|1[0-9]|2[0-4]|25(pre|rc))[^0-9]*$", string:lanman, icase:TRUE))
    security_hole(get_kb_item("SMB/transport"));
}
