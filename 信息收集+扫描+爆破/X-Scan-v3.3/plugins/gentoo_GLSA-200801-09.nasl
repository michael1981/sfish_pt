# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200801-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(30033);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200801-09");
 script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200801-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200801-09
(X.Org X server and Xfont library: Multiple vulnerabilities)


    regenrecht reported multiple vulnerabilities in various X server
    extension via iDefense:
    The XFree86-Misc extension does not properly sanitize a parameter
    within a PassMessage request, allowing the modification of a function
    pointer (CVE-2007-5760).
    Multiple functions in the XInput extension do not properly sanitize
    client requests for swapping bytes, leading to corruption of heap
    memory (CVE-2007-6427).
    Integer overflow vulnerabilities in the EVI extension and in the
    MIT-SHM extension can lead to buffer overflows (CVE-2007-6429).
    The TOG-CUP extension does not sanitize an index value in the
    ProcGetReservedColormapEntries() function, leading to arbitrary memory
    access (CVE-2007-6428).
    A buffer overflow was discovered in the Xfont library when
    processing PCF font files (CVE-2008-0006).
    The X server does not enforce restrictions when a user specifies a
    security policy file and attempts to open it (CVE-2007-5958).
  
Impact

    Remote attackers could exploit the vulnerability in the Xfont library
    by enticing a user to load a specially crafted PCF font file resulting
    in the execution of arbitrary code with the privileges of the user
    running the X server, typically root. Local attackers could exploit
    this and the vulnerabilities in the X.org extensions to gain elevated
    privileges. If the X server allows connections from the network, these
    vulnerabilities could be exploited remotely. A local attacker could
    determine the existence of arbitrary files by exploiting the last
    vulnerability or possibly cause a Denial of Service.
  
Workaround

    Workarounds for some of the vulnerabilities can be found in the X.Org
    security advisory as listed under References.
  
');
script_set_attribute(attribute:'solution', value: '
    All X.Org X server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xorg-server-1.3.0.0-r5"
    All X.Org Xfont library users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/libXfont-1.3.1-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5760');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5958');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6427');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6428');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6429');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0006');
script_set_attribute(attribute: 'see_also', value: 'http://lists.freedesktop.org/archives/xorg/2008-January/031918.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200801-09] X.Org X server and Xfont library: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.Org X server and Xfont library: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-base/xorg-server", unaffected: make_list("ge 1.3.0.0-r5"), vulnerable: make_list("lt 1.3.0.0-r5")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-libs/libXfont", unaffected: make_list("ge 1.3.1-r1"), vulnerable: make_list("lt 1.3.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
