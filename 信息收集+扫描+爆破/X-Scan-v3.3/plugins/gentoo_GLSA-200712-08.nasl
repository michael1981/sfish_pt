# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-08.xml
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
 script_id(29295);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200712-08");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-08
(AMD64 x86 emulation Qt library: Multiple vulnerabilities)


    The Qt versions used by the AMD64 x86 emulation Qt libraries were
    vulnerable to several flaws (GLSA 200708-16, GLSA 200710-28)
  
Impact

    An attacker could trigger one of the vulnerabilities by causing a Qt
    application to parse specially crafted text or Unicode strings, which
    may lead to the execution of arbitrary code with the privileges of the
    user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All AMD64 x86 emulation Qt library users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-qtlibs-20071114-r2"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-16.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-28.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-08] AMD64 x86 emulation Qt library: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AMD64 x86 emulation Qt library: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-emulation/emul-linux-x86-qtlibs", arch: "amd64", unaffected: make_list("ge 20071114-r2"), vulnerable: make_list("lt 20071114-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
