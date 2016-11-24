# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-28.xml
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
 script_id(27579);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200710-28");
 script_cve_id("CVE-2007-4137");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-28
(Qt: Buffer overflow)


    Dirk Mueller from the KDE development team discovered a boundary error
    in file qutfcodec.cpp when processing Unicode strings.
  
Impact

    A remote attacker could send a specially crafted Unicode string to a
    vulnerable Qt application, possibly resulting in the remote execution
    of arbitrary code with the privileges of the user running the
    application. Note that the boundary error is present but reported to be
    not exploitable in 4.x series.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Qt 3.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/qt-3.3.8-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4137');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-28] Qt: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Qt: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-libs/qt", unaffected: make_list("ge 3.3.8-r4"), vulnerable: make_list("lt 3.3.8-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
