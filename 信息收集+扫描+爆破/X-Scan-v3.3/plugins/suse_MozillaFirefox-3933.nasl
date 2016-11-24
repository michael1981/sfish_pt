
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27122);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  MozillaFirefox: Security update to version 2.0.0.5 (MozillaFirefox-3933)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaFirefox-3933");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Firefox to security update
version 2.0.0.5

Following security problems were fixed:

- MFSA 2007-18: Crashes with evidence of memory corruption

  The usual collection of stability fixes for crashes that
look suspicious but haven't been proven to be exploitable.

  25 were in the browser engine, reported by  Mozilla
developers and community members Bernd Mielke, Boris
Zbarsky,  David Baron, Daniel Veditz, Jesse Ruderman, Lukas
Loehrer, Martijn Wargers, Mats Palmgren, Olli Pettay, Paul
Nickerson,and  Vladimir Sukhoy (CVE-2007-3734)

  7 were in the JavaScript engine reported by Asaf Romano,
Jesse Ruderman, Igor Bukanov (CVE-2007-3735)

- MFSA 2007-19 / CVE-2007-3736: XSS using addEventListener
  and setTimeout

  moz_bug_r_a4 reported that scripts could be injected into
another site's context by exploiting a timing issue using
addEventLstener or setTimeout.

- MFSA 2007-20 / CVE-2007-3089: frame spoofing

  Ronen Zilberman and Michal Zalewski both reported that it
was possible to exploit a timing issue to inject content
into about:blank frames in a page.

- MFSA 2007-21 / CVE-2007-3737:  Privilege escallation
  using an event handler attached to an element not in the
  document

  Reported by moz_bug_r_a4.

- MFSA 2007-22 / CVE-2007-3285: File type confusion due to
  %00 in name

  Ronald van den Heetkamp reported that a filename URL
containing %00 (encoded null) can cause Firefox to
interpret the file extension differently than the
underlying Windows operating system potentially leading to
unsafe actions such as running a program.

- MFSA 2007-23 / CVE-2007-3670: Remote code execution by
  launching Firefox from Internet Explorer

  Greg MacManus of iDefense and Billy Rios of Verisign
independently reported that links containing a quote (')
character could be used in Internet Explorer to launch
registered URL Protocol handlers with extra command-line
parameters. Firefox and Thunderbird are among those which
can be launched, and both support a '-chrome' option that
could be used to run malware.

  This problem does not affect Linux.

- MFSA 2007-24 / CVE-2007-3656: unauthorized access to
  wyciwyg:// documents

  Michal Zalewski reported that it was possible to bypass
the same-origin checks and read from cached (wyciwyg)
documents

- MFSA 2007-25 / CVE-2007-3738: XPCNativeWrapper pollution

  shutdown and moz_bug_r_a4 reported two separate ways to
modify an XPCNativeWrapper such that subsequent access by
the browser would result in executing user-supplied code.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaFirefox-3933");
script_end_attributes();

script_cve_id("CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3089", "CVE-2007-3737", "CVE-2007-3285", "CVE-2007-3670", "CVE-2007-3656", "CVE-2007-3738");
script_summary(english: "Check for the MozillaFirefox-3933 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaFirefox-2.0.0.5-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaFirefox-translations-2.0.0.5-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
