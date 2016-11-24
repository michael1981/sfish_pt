#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(19699);
  script_version("$Revision: 1.14 $");

  name["english"] = "Unsupported Windows NT 4.0 Installation";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote operating system is not supported by its vendor any more." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Windows NT 4.0.

This operating system is no longer supported by Microsoft, so this
system is likely to contains remotely exploitable vulnerabilities that
may allow an attacker or a worm to take the complete control of the
remote system (MS05-027, MS05-043 ...)." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/ntserver/ProductInfo/Availability/Retiring.asp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Windows XP/2000/2003/2008." );
 script_set_attribute(attribute:"risk_factor", value:"High" );
script_end_attributes();


  summary["english"] = "Remote Host is running Windows NT 4.0";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  family["english"] = "Windows";
  script_family(english:family["english"]);

  script_dependencie("os_fingerprint.nasl","smb_nativelanman.nasl");
  exit (0);
}

include("global_settings.inc");

nt4 = 0;

os = get_kb_item("Host/OS");
if ( os && "Windows NT 4.0" >< os )
{
  conf = int(get_kb_item("Host/OS/Confidence"));
  if (report_paranoia > 1  || conf >= 70) nt4 ++;
}

os = get_kb_item ("Host/OS/smb") ;
if ( os && "Windows 4.0" >< os )
  nt4++;

if (nt4 != 0)
  security_hole (0);

