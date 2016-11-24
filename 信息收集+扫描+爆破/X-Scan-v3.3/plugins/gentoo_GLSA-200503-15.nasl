# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-15.xml
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
 script_id(17317);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200503-15");
 script_cve_id("CVE-2005-0605");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-15
(X.org: libXpm vulnerability)


    Chris Gilbert has discovered potentially exploitable buffer overflow
    cases in libXpm that weren\'t fixed in previous libXpm versions.
  
Impact

    A carefully-crafted XPM file could crash X.org, potentially allowing
    the execution of arbitrary code with the privileges of the user running
    the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All X.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose x11-base/xorg-x11
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0605');
script_set_attribute(attribute: 'see_also', value: 'https://bugs.freedesktop.org/show_bug.cgi?id=1920');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-15] X.org: libXpm vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.org: libXpm vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("rge 6.8.0-r5", "ge 6.8.2-r1"), vulnerable: make_list("lt 6.8.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
