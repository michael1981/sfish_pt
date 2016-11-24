#
# (C) Tenable Network Security, Inc.
#

# Nessus 3.0.3 or newer
if ( NASL_LEVEL < 3002 ) exit(0);

include("compat.inc");

if (description) {
  script_id(22869);
  script_version("$Revision: 1.13 $");

  script_name(english:"Software Enumeration (SSH)");
  script_summary(english:"Displays the list of packages installed on the remote software"); 
 
  script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate installed software on the remote host, via
SSH." );
  script_set_attribute(attribute:"description", value:
"This plugin lists the software installed on the remote host by calling
the appropriate command (rpm -qa on RPM-based Linux distributions,
qpkg, dpkg, etc...)" );
  script_set_attribute(attribute:"solution", value:
"Remove any software that is in compliance with your organization's
acceptable use and security policies." );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/uname");

  exit(0);
}


function report(os, buf)
{
 local_var report;
 report = string("\n",
            "Here is the list of packages installed on the remote ", os , " system : \n\n", buf);
 security_note(port:0, extra:report);
 exit(0);
}

list = make_array("Host/FreeBSD/pkg_info", "FreeBSD",
		  "Host/RedHat/rpm-list",  "Red Hat Linux",
		  "Host/CentOS/rpm-list",  "CentOS Linux",
		  "Host/Mandrake/rpm-list",  "Mandriva Linux",
		  "Host/SuSE/rpm-list",  "SuSE Linux",
		  "Host/VMware/rpm-list",  "VMware ESX",
		  "Host/Gentoo/qpkg-list",  "Gentoo Linux",
		  "Host/Debian/dpkg-l",    "Linux",
		  "Host/Slackware/packages", "Slackware Linux",
		  "Host/MacOSX/packages",   "Mac OS X",
		  "Host/Solaris/showrev",   "Solaris",
		  "Host/AIX/lslpp",	    "AIX",
		  "Host/HP-UX/swlist",      "HP-UX");


foreach item ( keys(list) ) 
{
 buf = get_kb_item(item);
 if ( buf ) report(os:list[item], buf:buf);
}

