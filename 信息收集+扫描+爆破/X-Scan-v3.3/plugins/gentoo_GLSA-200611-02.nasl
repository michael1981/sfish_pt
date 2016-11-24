# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200611-02.xml
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
 script_id(23626);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200611-02");
 script_cve_id("CVE-2006-4811");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200611-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200611-02
(Qt: Integer overflow)


    An integer overflow flaw has been found in the pixmap handling of Qt.
  
Impact

    By enticing a user to open a specially crafted pixmap image in an
    application using Qt, e.g. Konqueror, a remote attacker could be able
    to cause an application crash or the execution of arbitrary code with
    the rights of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Qt 3.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/qt-3.3.6-r4"
    All Qt 4.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/qt-4.1.4-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4811');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200611-02] Qt: Integer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Qt: Integer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-libs/qt", unaffected: make_list("ge 4.1.4-r2", "rge 3.3.6-r4", "rge 3.3.8", "rge 3.3.8b"), vulnerable: make_list("lt 4.1.4-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
