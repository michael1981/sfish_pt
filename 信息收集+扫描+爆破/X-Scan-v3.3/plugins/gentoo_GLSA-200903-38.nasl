# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-38.xml
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
 script_id(36013);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200903-38");
 script_cve_id("CVE-2007-6239", "CVE-2008-1612", "CVE-2009-0478");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-38 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-38
(Squid: Multiple Denial of Service vulnerabilities)


    The arrayShrink function in lib/Array.c can cause an array to
    shrink to 0 entries, which triggers an assert error. NOTE: this issue
    is due to an incorrect fix for CVE-2007-6239 (CVE-2008-1612).
    An invalid version number in a HTTP request may trigger an
    assertion in HttpMsg.c and HttpStatusLine.c (CVE-2009-0478).
  
Impact

    The issues allows for Denial of Service attacks against the service via
    an HTTP request with an invalid version number and other specially
    crafted requests.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Squid users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-proxy/squid-2.7.6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6239');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1612');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0478');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-05.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-38.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-38] Squid: Multiple Denial of Service vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: Multiple Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/squid", unaffected: make_list("ge 2.7.6"), vulnerable: make_list("lt 2.7.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
