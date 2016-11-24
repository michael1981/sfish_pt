# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-20.xml
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
 script_id(38161);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200904-20");
 script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0163", "CVE-2009-0164", "CVE-2009-0166");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-20
(CUPS: Multiple vulnerabilities)


    The following issues were reported in CUPS:
    iDefense
    reported an integer overflow in the _cupsImageReadTIFF() function in
    the "imagetops" filter, leading to a heap-based buffer overflow
    (CVE-2009-0163).
    Aaron Siegel of Apple Product Security
    reported that the CUPS web interface does not verify the content of the
    "Host" HTTP header properly (CVE-2009-0164).
    Braden Thomas and
    Drew Yao of Apple Product Security reported that CUPS is vulnerable to
    CVE-2009-0146, CVE-2009-0147 and CVE-2009-0166, found earlier in xpdf
    and poppler.
  
Impact

    A remote attacker might send or entice a user to send a specially
    crafted print job to CUPS, possibly resulting in the execution of
    arbitrary code with the privileges of the configured CUPS user -- by
    default this is "lp", or a Denial of Service. Furthermore, the web
    interface could be used to conduct DNS rebinding attacks.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-print/cups-1.3.10"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0146');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0147');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0163');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0164');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0166');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-20] CUPS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CUPS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-print/cups", unaffected: make_list("ge 1.3.10"), vulnerable: make_list("lt 1.3.10")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
