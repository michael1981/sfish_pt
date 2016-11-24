# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-24.xml
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
 script_id(28263);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-24");
 script_cve_id("CVE-2007-5339", "CVE-2007-5340");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-24
(Mozilla Thunderbird: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in Mozilla Thunderbird\'s
    HTML browser engine (CVE-2007-5339) and JavaScript engine
    (CVE-2007-5340) that can be exploited to cause a memory corruption.
  
Impact

    A remote attacker could entice a user to read a specially crafted email
    that could trigger one of the vulnerabilities, possibly leading to the
    execution of arbitrary code.
  
Workaround

    There is no known workaround at this time for all of these issues, but
    some of them can be avoided by disabling JavaScript.
  
');
script_set_attribute(attribute:'solution', value: '
    All Mozilla Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-2.0.0.9"
    All Mozilla Thunderbird binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-2.0.0.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5339');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5340');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-14.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-24] Mozilla Thunderbird: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla Thunderbird: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 2.0.0.9"), vulnerable: make_list("lt 2.0.0.9")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 2.0.0.9"), vulnerable: make_list("lt 2.0.0.9")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
