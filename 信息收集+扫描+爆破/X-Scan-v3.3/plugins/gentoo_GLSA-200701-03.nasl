# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-03.xml
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
 script_id(23992);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200701-03");
 script_cve_id("CVE-2006-6497", "CVE-2006-6500", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6505");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-03
(Mozilla Thunderbird: Multiple vulnerabilities)


    Georgi Guninski and David Bienvenu discovered buffer overflows in the
    processing of long "Content-Type:" and long non-ASCII MIME headers.
    Additionally, Frederik Reiss discovered a heap-based buffer overflow in
    the conversion of a CSS cursor. Different vulnerabilities involving
    memory corruption in the browser engine were also fixed. Mozilla
    Thunderbird also contains less severe vulnerabilities involving
    JavaScript and Java.
  
Impact

    An attacker could entice a user to view a specially crafted email that
    will trigger one of these vulnerabilities, possibly leading to the
    execution of arbitrary code. An attacker could also perform cross-site
    scripting attacks, leading to the exposure of sensitive information,
    like user credentials. Note that the execution of JavaScript or Java
    applets is disabled by default and enabling it is strongly discouraged.
  
Workaround

    There are no known workarounds for all the issues at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mozilla Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-1.5.0.9"
    All Mozilla Thunderbird binary release users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-1.5.0.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6497');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6500');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6501');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6502');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6503');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6505');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-03] Mozilla Thunderbird: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Thunderbird: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 1.5.0.9"), vulnerable: make_list("lt 1.5.0.9")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 1.5.0.9"), vulnerable: make_list("lt 1.5.0.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
