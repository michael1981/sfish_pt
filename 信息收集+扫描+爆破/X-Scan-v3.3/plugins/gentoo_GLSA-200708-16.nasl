# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-16.xml
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
 script_id(25944);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200708-16");
 script_cve_id("CVE-2007-3388");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-16
(Qt: Multiple format string vulnerabilities)


    Tim Brown of Portcullis Computer Security Ltd and Dirk Mueller of KDE
    reported multiple format string errors in qWarning() calls in files
    qtextedit.cpp, qdatatable.cpp, qsqldatabase.cpp, qsqlindex.cpp,
    qsqlrecord.cpp, qglobal.cpp, and qsvgdevice.cpp.
  
Impact

    An attacker could trigger one of the vulnerabilities by causing a Qt
    application to parse specially crafted text, which may lead to the
    execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Qt 3 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "=x11-libs/qt-3*"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3388');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-16] Qt: Multiple format string vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Qt: Multiple format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "x11-libs/qt", unaffected: make_list("ge 3.3.8-r3"), vulnerable: make_list("lt 3.3.8-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
