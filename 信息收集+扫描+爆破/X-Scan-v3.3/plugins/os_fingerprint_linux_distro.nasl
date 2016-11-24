#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25335);
  script_version("$Revision: 1.8 $");

  name["english"] = "OS Identification : Linux Distribution";
  script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"By looking at certain files it is possible to identify the
remote operating system." );
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type and 
version by looking at some files on the remote operating system
(/etc/redhat-release on Red Hat, etc...)." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

 
  summary["english"] = "Determines the remote operating system";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencies("ssh_get_info.nasl", "os_fingerprint_uname.nasl");
  script_require_keys("Host/OS/uname");
  exit(0);
}


kernel = get_kb_item("Host/OS/uname");
if ( ! kernel || "Linux Kernel" >!< kernel ) exit(0);

os = get_kb_item("Host/RedHat/release");
if ( os )
{
 if ( get_kb_item("Host/Oracle/Linux") )
	os = ereg_replace(pattern:"^Red Hat", replace:"Oracle Unbreakable Linux", string:os);
}
if ( ! os ) os = get_kb_item("Host/CentOS/release");
if ( ! os ) os = get_kb_item("Host/Mandrake/release");
if ( ! os ) {
	os = get_kb_item("Host/SuSE/release");
	if ( os )
	{
	  v = eregmatch(string: os, pattern: " (open)?SUSE ([A-Z][a-z]+ )*([0-9.]+) ");
	  if (! isnull(v))
	    os = "SuSE " + v[3];
	  else if ("SUSE" >< os)
	  {
	    os -= "SUSE"; os = "SuSE" + os;
	  }
	}
}
if ( ! os ) 
	{
	  os = get_kb_item("Host/Gentoo/release");
	  if ( os ) os = "Gentoo " + os;
	}
if ( ! os ) os = get_kb_item("Host/Slackware/release");
if ( ! os ) {
	os = get_kb_item("Host/Ubuntu/release");
	if ( os ) os = "Ubuntu " + os;
	}
if ( ! os ) {
	os = get_kb_item("Host/Debian/release");
	if ( os ) os = "Debian " + os;
	}

if ( os )
{
 os = chomp(os);
 set_kb_item(name:"Host/OS/LinuxDistribution", value:kernel +" on " + os);
 set_kb_item(name:"Host/OS/LinuxDistribution/Type", value:"general-purpose");
 set_kb_item(name:"Host/OS/LinuxDistribution/Confidence", value:100);
}

