# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-18.xml
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
 script_id(26216);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200709-18");
 script_cve_id("CVE-2007-4538", "CVE-2007-4539", "CVE-2007-4543");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-18
(Bugzilla: Multiple vulnerabilities)


    Masahiro Yamada found that from the 2.17.1 version, Bugzilla does not
    properly sanitize the content of the "buildid" parameter when filing
    bugs (CVE-2007-4543). The next two vulnerabilities only affect Bugzilla
    2.23.3 or later, hence the stable Gentoo Portage tree does not contain
    these two vulnerabilities: Loic Minier reported that the
    "Email::Send::Sendmail()" function does not properly sanitise "from"
    email information before sending it to the "-f" parameter of
    /usr/sbin/sendmail (CVE-2007-4538), and Frederic Buclin discovered that
    the XML-RPC interface does not correctly check permissions in the
    time-tracking fields (CVE-2007-4539).
  
Impact

    A remote attacker could trigger the "buildid" vulnerability by sending
    a specially crafted form to Bugzilla, leading to a persistent XSS, thus
    allowing for theft of credentials. With Bugzilla 2.23.3 or later, an
    attacker could also execute arbitrary code with the permissions of the
    web server by injecting a specially crafted "from" email address and
    gain access to normally restricted time-tracking information through
    the XML-RPC service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Bugzilla users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose www-apps/bugzilla
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4538');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4539');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4543');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-18] Bugzilla: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Bugzilla: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/bugzilla", unaffected: make_list("rge 2.20.5", "rge 2.22.3", "ge 3.0.1", "rge 2.22.5", "rge 2.20.6"), vulnerable: make_list("lt 3.0.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
