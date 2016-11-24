#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33850);
  script_version("$Revision: 1.26 $");
  script_name(english: "Unsupported Linux / Unix Operating System");
  script_summary(english: "Check if the operating system is still maintained");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an obsolete operating system." );
 script_set_attribute(attribute:"description", value:
"According to its version, the remote Linux or Unix operating system
is obsolete and no longer maintained by its vendor or provider. 

Lack of support implies that no new security patches will be
released for it." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
 script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english: "General");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencie("os_fingerprint.nasl");
  script_require_keys("Host/OS");
  exit(0);
}

function report_and_exit(txt)
{
  security_hole(port: 0, extra: '\n' + txt);
  set_kb_item(name: 'Host/OS/obsolete', value: TRUE);
  exit(0);
}

# Beware of version numbers like 2.5 / 2.5.1; if 2.5.1 is not obsolete 
# and 2.5 is, check the version before calling this function.
function check(os, dates, latest, url, name)
{
  local_var	k, r;

  r = "";
  foreach k (keys(dates))
    if (k >< os)
    {
      if (name && name >!< k) r = strcat(r, name, " ");
      r =  strcat(r, k, ' support ended');
      if (dates[k]) r = strcat(r, ' on ', dates[k]);
      r = strcat(r, '.\n');
      if (latest) r = strcat(r, 'Upgrade to ', latest, '.\n');
      if (url)  r = strcat(r, '\nFor more information, see : ', url, '\n\n');
      report_and_exit(txt: r);
     }
}

uname = get_kb_item("Host/uname");

os = get_kb_item("Host/OS");
conf = get_kb_item("Host/OS/Confidence");
if (conf <= 70) os = NULL;	# Avoid FP
if ( os && '\n' >< os ) os = NULL; # Avoid FP++

# Handle very old distros
if ( strlen(os) == 0 && 
     max_index(keys(get_kb_list("Host/etc/*"))) == 0)
  exit(0);


rep = '';


#### Mandrake / Mandriva Linux ####
# http://www.linuxtoday.com/infrastructure/2003100201126NWMDSS
# http://www.mandriva.com/en/mandriva-product-lifetime-policy
# http://www.mandriva.com/en/security/advisories

v = make_array(
"MDK2007.0",	"2008-04-11",	# or later?
"MDK2006",	"2007-04-11",	# or later?
"MDK10.1",	"2006-02-22",	# or later?
"MDK10.0",	"2005-09-20",	# or later?
"MDK9.2",	"2005-03-15",	# or later?
"MDK9.1",	"2004-08-31",	# or later?
"MDK9.0",	"2004-03-31",
"MDK8.2",	"2003-09-30",
"MDK8.1",	"2003-03-31",
"MDK8.0",	"2003-03-31",
"MDK7.2",	"2003-03-31",
"MDK7.1",	"2002-10-15",	# also Corporate Server 1.0.1
"MDK7.0",	"2001-04-18",
"MDK6.1",	"2001-04-18",
"MDK6",		"2001-04-18",
"MDK5",		""
#   Single Network Firewall 7.2	n/a		June 1, 2003
#   Multi Network Firewall 8.2	n/a		December 12, 2004
);

check( os: os, dates: v, 
       latest: "Mandriva Linux 2009", 
       url: "http://www.mandriva.com/en/mandriva-product-lifetime-policy");

# Old Mandrake need to be tested *before* Red Hat.

os2 = get_kb_item("Host/etc/mandrake-release");
if (strlen(os2) == 0)
{
  os2 = get_kb_item("Host/etc/redhat-release");
  if ("Mandrake" >!< os2) os2 = NULL;
}

if (strlen(os2) > 0)
{
 foreach k (keys(v))
 {
   k2 = str_replace(find: "MDK", replace: "release ", string: k);
   v2[k2] = v[k];
 }
 check( os: os2, dates: v2, name: "Linux Mandrake",
        latest: "Mandriva Linux 2009", 
        url: "http://www.mandriva.com/en/mandriva-product-lifetime-policy");
}

#### Fedora Linux / old RedHat ####
# http://fedoraproject.org/wiki/LifeCycle/EOL
v = make_array(
"Fedora release 9",		"2009-07-10",
"Fedora release 8",		"2009-01-07",
"Fedora release 7",		"2008-06-13",
"Fedora Core release 6",	"2007-12-07",
"Fedora Core release 5",	"2007-07-02",
"Fedora Core release 4",	"2006-08-07",
"Fedora Core release 3",	"2006-01-16",
"Fedora Core release 2",	"2005-04-11",
"Fedora Core release 1",	"2004-09-20" );
check( os: os, dates: v, 
       latest: "Fedora 12", 
       url: "http://fedoraproject.org/wiki/LifeCycle/EOL");

v = make_array (
"Red Hat Linux release 9",	"2004-04-30",
"release 8",	"2004-01-15",	# 8.0
"release 7",	"2004-01-15",
"release 6",	"",
"release 5",	"",
"release 4",	"",
"release 3",	"" );
# This won't work against old Red Hat currently.
os2 = get_kb_item("Host/etc/redhat-release");
if (os2 =~ '^(Red Hat Linux )?release ')
 check( os: os2, dates: v, name: "Red Hat Linux",
        latest: "Fedora 11", 
        url: "http://fedoraproject.org/wiki/LifeCycle/EOL");

#### Redhat Enterprise Linux ####

# http://www.redhat.com/security/updates/errata/
#
# os looks like 
# "Red Hat Enterprise Linux ES release 4 (Nahant)"
#
# RHEL 3 will be obsolete on October 31, 2010

v = make_array (
  "Red Hat Enterprise Linux AS 2.1",            "2009-05-31",
  "Red Hat Enterprise Linux ES 2.1",            "2009-05-31",
  "Red Hat Enterprise Linux WS 2.1",            "2009-05-31",
  "Red Hat Linux Advanced Server 2.1",          "2009-05-31",
  "Red Hat Linux Advanced Workstation 2.1",     "2009-05-31"
);
os2 = get_kb_item("Host/etc/redhat-release");
if (strlen(os2) && os2 =~ '^Red Hat (Linux Advanced|Enterprise)')
  check(
    os     : os2, 
    dates  : v, 
    latest : "Red Hat Enterprise Linux 5", 
    url    : "http://www.redhat.com/security/updates/errata/"
  );


#### CentOS ####

# os looks like 
# "CentOS release 3.6"

v = make_array (
  "CentOS release 2",    "2009-05-31"
);
os2 = get_kb_item("Host/etc/redhat-release");
if (strlen(os2) && os2 =~ '^CentOS')
  check(
    os     : os2, 
    dates  : v, 
    latest : "CentOS 5.3", 
    url    : "http://www.nessus.org/u?b549f616"
  );


#### SuSE Linux ####

# self-support => no patch!
# http://support.novell.com/lifecycle/lcSearchResults.jsp?sl=suse	
# SUSE Linux Enterprise Desktop 10 		31 Jul 2011	31 Jul 2013
# SUSE Linux Enterprise Point of Service 10 	31 Jul 2011	31 Jul 2013
# SUSE Linux Enterprise Real Time 10 SP1 	31 Jul 2011	31 Jul 2013
# SUSE Linux Enterprise Server 10 		31 Jul 2011	31 Jul 2013
# SUSE LINUX Enterprise Server 9 		30 Jul 2009	30 Jul 2011
# SUSE Linux Enterprise Thin Client 10 		31 Jul 2011	31 Jul 2013

# http://www.linuxtoday.com/infrastructure/2003100201126NWMDSS

v = make_array(
"SuSE SLED1.0",		"2007-11-30",
"SuSE SLED8",		"2007-11-30",
"SuSE 10.0",		"2007-12-20",
"SuSE 9.3",		"2007-06-19",
"SuSE 9",		"2007-06-19",
"SuSE 8",		"",
"SuSE 7.2",		"2003-10-01",
"SuSE 7",		"2003-10-01" );

check( os: os, dates: v, 
       latest: "OpenSUSE 11 / SUSE Linux Enterprise 10", 
       url: "http://support.novell.com/lifecycle/lcSearchResults.jsp?sl=suse" );

v = make_array(
"SUSE LINUX Openexchange Server 4.0",	"2007-10-14",
"SUSE LINUX Openexchange Server 4.1",	"2007-11-10",
"SUSE LINUX Retail Solution 8",		"2007-11-30",
"SUSE LINUX Standard Server 8",		"2007-11-30" );
# This wouldn't work against the normalized names
os2 = get_kb_item("Host/etc/suse-release");
if (os2)
 check( os: os2, dates: v, 
        latest: "OpenSUSE 11 / SUSE Linux Enterprise 10", 
        url: "http://support.novell.com/lifecycle/lcSearchResults.jsp?sl=suse" );


#### Gentoo Linux ####
# testing Gentoo does not make sense - but we may have a look at the profile
# See also gentoo_unmaintained_packages.nasl

#### Debian Linux ####

v = make_array(
"Debian 3.1",	"2008-03-31",
"Debian 3.0",	"2006-06-30",
"Debian 2.2",	"2003-06-30",
"Debian 2.1",	"",
"Debian 2.0",	"" );

check( os: os, dates: v, 
       latest: "Debian Linux 5.0.2", 
       url: "http://www.debian.org/releases/" );

#### Ubuntu Linux ####
# https://help.ubuntu.com/community/UpgradeNotes#Unsupported%20(Obsolete)%20Versions
# http://en.wikipedia.org/wiki/Ubuntu_(Linux_distribution)
# http://www.ubuntu.com/products/whatisubuntu/serveredition/benefits/lifecycle
# Regular versions: Security patches are delivered for 18 months
# LTS versions : Security patches are delivered for 5 years (6.06, 8.04, 10.04...)

v = make_array(
# 8.10 will expire in 2010-04
# 8.04 = LTS
  "Ubuntu 7.10",	"2009-04-18",
  "Ubuntu 7.04",	"2008-10-19",
  "Ubuntu 6.10",	"2008-04-26",
  # nb: Ubuntu 6.06 is on LTS
  "Ubuntu 5.10",	"2007-04-13",
  "Ubuntu 5.04",	"2006-10-31",
  "Ubuntu 4.10",	"2006-04-30"
);
check( os: os, dates: v, 
       latest: "Ubuntu 9.10", 
       url: "http://www.nessus.org/u?5939f44b" );

#### Slackware ####

# No official policy. Critical security patches are still backported into
# old versions (e.g. libpng-1.2.27-i386-1_slack8.1.tgz on 2008-04-29)

#### AIX ####
# http://en.wikipedia.org/wiki/AIX_operating_system
# http://www-306.ibm.com/software/support/systemsp/lifecycle/

v = make_array(
"AIX 5.2", "2009-04-30",
"AIX 5.1", "2006-04-01",
"AIX 4", "",
"AIX 3", "");

check( os: os, dates: v, 
       latest: "AIX 6.1", 
       url: "http://www.nessus.org/u?ce9a8c24");

#### HP-UX ####
# http://www.hp.com/softwarereleases/releases-media2/notices/0303.htm
# http://www.hp.com/softwarereleases/releases-media2/latest/06_08/0806_Update_letter.pdf
v = make_array(
"HP-UX 10.20",	"2003-07-01",
"HP-UX 11.0",	"2006-12-31",	# (designated with VUF number B.11.00) 
"HP-UX B.11.00", "2006-12-31",	# Not sure we store it like this
# "HP-UX 11i??", "2003-03-01",	# HP-UX 11i Version 1.5 for Itanium
"HP-UX 7", "",
"HP-UX 8", "",
"HP-UX 9", "",
"HP-UX 10",	"2003-07-01" );

check( os: os, dates: v,
       latest: "HP-UX 11i V3",
       url: "http://www.hp.com/softwarereleases/releases-media2/notices/0303.htm");

#### Solaris ####

# http://www.sun.com/service/eosl/solaris/solaris_vintage_eol_5.2005.xml
# http://www.sun.com/service/eosl/eosl_solaris.html

v = make_array(
"SunOS 5.7",	"2008-08-15",
"SunOS 5.6",	"2006-07-23",
"SunOS 5.5.1",	"2005-09-22",
"SunOS 5.5",	"2003-12-27",
"SunOS 5.4",	"2003-09-30",
"SunOS 5.3",	"2002-06-01",
"SunOS 5.2",	"1999-05-01",
"SunOS 5.1",	"1999-04-15",
"SunOS 5.0",	"1999-01-01",
"SunOS 4.1.4",	"2000-09-30",
# 4.1.3_U1 in fact
"SunOS 4.1.3",	"2000-09-30",
# Solaris 1.1 & C	06/03/96
"SunOS 4.1.2",	"2000-01-06",
"SunOS 4.1.1",	"2000-01-06",
"SunOS 4",	"1999-09-30" );

check( os: os, dates: v,
       latest: "SunOS 5.11 / Solaris 11",
       url: "http://www.sun.com/service/eosl/solaris/solaris_vintage_eol_5.2005.xml" );

#### FreeBSD ####
# http://www.auscert.org.au/render.html?it=9392
# http://www.daemonology.net/blog/2006-10-01-upcoming-freebsd-eols.html
v = make_array(
"FreeBSD 4",	"2007-01-31",	# 4.11
"FreeBSD 5.3",	"2006-10-31",
"FreeBSD 5.4",	"2006-10-31",
"FreeBSD 5.5",	"2008-05-31",
"FreeBSD 5",	"2008-05-31",	# 5.5
"FreeBSD 6.0",	"2006-11-30",
"FreeBSD 6.1",	"2008-05-31", 
"FreeBSD 6.2",	"2008-05-31", 
"FreeBSD 3",	"" );

# "FreeBSD 6.3", "January 31, 2010"
# "FreeBSD 7.0", "February 28, 2009"

check( os: os, dates: v,
       latest: "FreeBSD 6.4 or 7.2",
       url: "http://www.freebsd.org/security/");

os2 = get_kb_item("Host/FreeBSD/release");
if (os2)
  check( os: str_replace(string: os2, find: "FreeBSD-", replace: "FreeBSD "),
  	 dates: v,
       	 latest: "FreeBSD 6.4 or 7.2",
       	 url: "http://www.freebsd.org/security/");

#### OpenBSD ####

v = make_array(
"OpenBSD 4.3",	"",	# ?
"OpenBSD 4.2",	"",	# ?
"OpenBSD 4.1",	"2008-06-30",	# ?
"OpenBSD 4.0",	"2007-11-01",	# ?
"OpenBSD 3.9",	"2007-06-30",	# ?
"OpenBSD 3.8",	"2006-11-13",
"OpenBSD 3.7",	"2006-05-18",
"OpenBSD 3.6",	"2006-10-30",	# ?
"OpenBSD 3.5",	"2005-06-30",
"OpenBSD 3.4",	"2004-10-30",
"OpenBSD 3.3",	"2004-05-05",	#?
"OpenBSD 3.2",	"2003-11-04",
"OpenBSD 3.1",	"2003-06-01",
"OpenBSD 3.0",	"2002-12-01",
"OpenBSD 2.9",	"2002-06-01",
"OpenBSD 2.",	"",
"OpenBSD 1.",	"" );

check( os: os, dates: v,
       latest: "OpenBSD 4.6",
       url: "http://www.openbsd.org/security.html");

#### Other very old distros ####
# uname:
# Linux CorelLinux 2.2.12 #1 SMP Tue Nov 9 14:11:25 EST 1999 i686 unknown

v = make_array("Corel Linux", "");
check( os: os, dates: v, url: "http://en.wikipedia.org/wiki/Corel_Linux");

v = make_array("OpenLinux", "");
check( os: os, dates: v, url: "http://en.wikipedia.org/wiki/Openlinux");

v = make_array("Trustix", "2007-12-31");
check( os: os, dates: v, url: "http://en.wikipedia.org/wiki/Trustix");


#
# Mac OS X 
#
v = make_array(
"Mac OS X 10.0", "",
"Mac OS X 10.1", "",
"Mac OS X 10.2", "",
"Mac OS X 10.3", "",
"Mac OS X 10.4", "");
  check( os: os,
  	 dates: v,
       	 latest: "Mac OS X 10.6",
       	 url: "http://www.apple.com/macosx/");
