#
# (C) Tenable Network Security
#
#
# Thanks to Keith Yong for suggesting this


include("compat.inc");

if(description)
{
  script_id(21626);
  script_version("$Revision: 1.8 $");

  name["english"] = "Unsupported Windows 95/98/ME Installation";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of Microsoft Windows that is no
longer supported by Microsoft." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Windows 9x (95, 98
or ME).  Windows 95 support ended on December 31st, 2001 and Windows
98/ME ended on July 11th 2006. 

A lack of support implies that no new security patches will be
released for this operating system." );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/gp/lifean18" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Windows XP or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  summary["english"] = "Remote Host is running Windows 95/98/ME";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  family["english"] = "Windows";
  script_family(english:family["english"]);

  script_dependencie("os_fingerprint.nasl","smb_nativelanman.nasl");
  script_require_keys("Host/OS");
  exit (0);
}
include("global_settings.inc");

os = get_kb_item("Host/OS");
if (os && ereg(pattern:"Windows (95|98|ME)", string:os) )
{
  conf = int(get_kb_item("Host/OS/Confidence"));
  if (report_paranoia > 1 || conf >= 70) security_hole(0);
}


