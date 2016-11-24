# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-17.xml
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
 script_id(35188);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200812-17");
 script_cve_id("CVE-2008-1447", "CVE-2008-2376", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-17
(Ruby: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in the Ruby interpreter
    and its standard libraries. Drew Yao of Apple Product Security
    discovered the following flaws:
    Arbitrary code execution
    or Denial of Service (memory corruption) in the rb_str_buf_append()
    function (CVE-2008-2662).
    Arbitrary code execution or Denial
    of Service (memory corruption) in the rb_ary_stor() function
    (CVE-2008-2663).
    Memory corruption via alloca in the
    rb_str_format() function (CVE-2008-2664).
    Memory corruption
    ("REALLOC_N") in the rb_ary_splice() and rb_ary_replace() functions
    (CVE-2008-2725).
    Memory corruption ("beg + rlen") in the
    rb_ary_splice() and rb_ary_replace() functions (CVE-2008-2726).
    Furthermore, several other vulnerabilities have been reported:
    Tanaka Akira reported an issue with resolv.rb that enables
    attackers to spoof DNS responses (CVE-2008-1447).
    Akira Tagoh
    of RedHat discovered a Denial of Service (crash) issue in the
    rb_ary_fill() function in array.c (CVE-2008-2376).
    Several
    safe level bypass vulnerabilities were discovered and reported by Keita
    Yamaguchi (CVE-2008-3655).
    Christian Neukirchen is credited
    for discovering a Denial of Service (CPU consumption) attack in the
    WEBRick HTTP server (CVE-2008-3656).
    A fault in the dl module
    allowed the circumvention of taintness checks which could possibly lead
    to insecure code execution was reported by "sheepman"
    (CVE-2008-3657).
    Tanaka Akira again found a DNS spoofing
    vulnerability caused by the resolv.rb implementation using poor
    randomness (CVE-2008-3905).
    Luka Treiber and Mitja Kolsek
    (ACROS Security) disclosed a Denial of Service (CPU consumption)
    vulnerability in the REXML module when dealing with recursive entity
    expansion (CVE-2008-3790).
  
Impact

    These vulnerabilities allow remote attackers to execute arbitrary code,
    spoof DNS responses, bypass Ruby\'s built-in security and taintness
    checks, and cause a Denial of Service via crash or CPU exhaustion.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Ruby users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/ruby-1.8.6_p287-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1447');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2376');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2662');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2663');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2664');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2725');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2726');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3655');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3656');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3657');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3790');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3905');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-17] Ruby: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ruby: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/ruby", unaffected: make_list("ge 1.8.6_p287-r1"), vulnerable: make_list("lt 1.8.6_p287-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
