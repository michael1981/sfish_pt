# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-06.xml
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
 script_id(24773);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200703-06");
 script_cve_id("CVE-2006-4811");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-06
(AMD64 x86 emulation Qt library: Integer overflow)


    An integer overflow flaw has been found in the pixmap handling of Qt,
    making the AMD64 x86 emulation Qt library vulnerable as well.
  
Impact

    By enticing a user to open a specially crafted pixmap image in an
    application using the AMD64 x86 emulation Qt library, a remote attacker
    could cause an application crash or the remote execution of arbitrary
    code with the rights of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All AMD64 x86 emulation Qt library users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/emul-linux-x86-qtlibs-10.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200611-02.xml');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4811');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-06] AMD64 x86 emulation Qt library: Integer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AMD64 x86 emulation Qt library: Integer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-emulation/emul-linux-x86-qtlibs", unaffected: make_list("ge 10.0"), vulnerable: make_list("lt 10.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
