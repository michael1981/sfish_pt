# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-18.xml
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
 script_id(24867);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200703-18");
 script_cve_id("CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-1282");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-18
(Mozilla Thunderbird: Multiple vulnerabilities)


    Georgi Guninski reported a possible integer overflow in the code
    handling text/enhanced or text/richtext MIME emails. Additionally,
    various researchers reported errors in the JavaScript engine
    potentially leading to memory corruption. Additionally, the binary
    version of Mozilla Thunderbird includes a vulnerable NSS library which
    contains two possible buffer overflows involving the SSLv2 protocol.
  
Impact

    An attacker could entice a user to read a specially crafted email that
    could trigger one of the vulnerabilities, some of them being related to
    Mozilla Thunderbird\'s handling of JavaScript, possibly leading to the
    execution of arbitrary code.
  
Workaround

    There is no known workaround at this time for all of these issues, but
    some of them can be avoided by disabling JavaScript. Note that the
    execution of JavaScript is disabled by default and enabling it is
    strongly discouraged.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mozilla Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-1.5.0.10"
    All Mozilla Thunderbird binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-1.5.0.10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0008');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0009');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0775');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0776');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0777');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1282');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-18] Mozilla Thunderbird: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Thunderbird: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 1.5.0.10"), vulnerable: make_list("lt 1.5.0.10")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 1.5.0.10"), vulnerable: make_list("lt 1.5.0.10")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
