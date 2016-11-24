# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200809-18.xml
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
 script_id(34299);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200809-18");
 script_cve_id("CVE-2008-1389", "CVE-2008-3912", "CVE-2008-3913", "CVE-2008-3914");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200809-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200809-18
(ClamAV: Multiple Denials of Service)


    Hanno boeck reported an error in libclamav/chmunpack.c when processing
    CHM files (CVE-2008-1389). Other unspecified vulnerabilites were also
    reported, including a NULL pointer dereference in libclamav
    (CVE-2008-3912), memory leaks in freshclam/manager.c (CVE-2008-3913),
    and file descriptor leaks in libclamav/others.c and libclamav/sis.c
    (CVE-2008-3914).
  
Impact

    A remote attacker could entice a user or automated system to scan a
    specially crafted CHM, possibly resulting in a Denial of Service
    (daemon crash). The other attack vectors mentioned above could also
    result in a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.94"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1389');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3912');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3913');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3914');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200809-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200809-18] ClamAV: Multiple Denials of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Multiple Denials of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.94"), vulnerable: make_list("lt 0.94")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
